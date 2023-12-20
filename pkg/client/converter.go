package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/Hicky1025/srview/pkg/converter"
	"github.com/Hicky1025/srview/pkg/bpf"
	"github.com/Hicky1025/srview/pkg/ipfix"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type Stats struct {
	Count     int64
	DelayMean int64
	DelayMin  int64
	DelayMax  int64
	DelaySum  int64
}

type StatsMap struct {
	Mu sync.RWMutex
	Db map[converter.ProbeData]*Stats
}

type Converter struct {
	statsMap *StatsMap
	bootTime time.Time
	xdp      *bpf.Xdp
}

func NewConverter(ingressIfName string) *Converter {
	bootTime, err := getSystemBootTime()
	if err != nil {
		log.Fatalf("Could not get boot time: %s", err)
	}

	statsMap := StatsMap{Db: make(map[converter.ProbeData]*Stats)}

	iface, err := net.InterfaceByName(ingressIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ingressIfName, err)
	}

	// xdpプログラムをロード
	xdp, err := bpf.ReadXdpObjects(&ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 256,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Could not load XDP program: %+v\n", ve)
		}
	}

	// xdpプログラムをアタッチ
	if err = xdp.Attach(iface); err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")


	return &Converter{
		statsMap: &statsMap,
		bootTime: bootTime,
		xdp:      xdp,
	}
}

func (m *Converter) Run(flowChan chan []ipfix.FieldValue, interval time.Duration) error {
	eg, ctx := errgroup.WithContext(context.Background())

	eg.Go(func() error {
		return m.Read(ctx)
	})
	eg.Go(func() error {
		return m.Send(ctx, flowChan, interval)
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

func (m *Converter) Read(ctx context.Context) error {
	perfEvent, err := m.xdp.NewPerfReader()
	if err != nil {
		log.Fatalf("Could not obtain perf reader: %s", err)
	}

	var metadata bpf.XdpMetaData
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			eventData, err := perfEvent.Read()
			if err != nil {
				log.Fatalf("Could not read from bpf perf map:")
			}

			reader := bytes.NewReader(eventData.RawSample)

			if err := binary.Read(reader, binary.LittleEndian, &metadata); err != nil {
				log.Fatalf("Could not read from reader: %s", err)
			}

			metadata_size := unsafe.Sizeof(metadata)
			if len(eventData.RawSample)-int(metadata_size) <= 0 {
				continue
			}

			receivedNano := m.bootTime.Add(time.Duration(metadata.ReceivedNano) * time.Nanosecond)
			SentNano := time.Unix(int64(metadata.SentSec), int64(metadata.SentSubsec))

			delay := receivedNano.Sub(SentNano)

			probeData, err := converter.Parse(eventData.RawSample[metadata_size:])
			if err != nil {
				log.Fatalf("Could not parse the packet: %s", err)
			}

			delayMicro := delay.Microseconds()

			m.statsMap.Mu.Lock()
			if value, ok := m.statsMap.Db[*probeData]; !ok {
				m.statsMap.Db[*probeData] = &Stats{
					Count:     1,
					DelayMean: delayMicro,
					DelayMin:  delayMicro,
					DelayMax:  delayMicro,
					DelaySum:  delayMicro,
				}
			} else {
				value.Count = value.Count + 1

				if delayMicro < value.DelayMin {
					value.DelayMin = delayMicro
				}

				if delayMicro > value.DelayMax {
					value.DelayMax = delayMicro
				}

				value.DelaySum = value.DelaySum + delayMicro
				value.DelayMean = value.DelaySum / value.Count
			}
			m.statsMap.Mu.Unlock()
		}
	}
}

func (m *Converter) Send(ctx context.Context, flowChan chan []ipfix.FieldValue, intervalSec time.Duration) error {
	ticker := time.NewTicker(intervalSec * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Print("test1")
		select {
		case <-ctx.Done():
			log.Print("test2")
			return nil
		default:
			m.statsMap.Mu.Lock()
			log.Print("test3")
			for probeData, stat := range m.statsMap.Db {
				dCnt := uint64(stat.Count)

				sl := []ipfix.SRHSegmentIPv6{}
				for _, seg := range probeData.Segments {
					if seg == "" {
						break
					}
					ipSeg, _ := netip.ParseAddr(seg)

					// Ignore zero values received from bpf map
					log.Print("test5")
					if ipSeg == netip.IPv6Unspecified() {
						break
					}
					seg := ipfix.SRHSegmentIPv6{Val: ipSeg}
					sl = append(sl, seg)
				}

				actSeg, _ := netip.ParseAddr(probeData.Segments[probeData.SegmentsLeft])

				f := []ipfix.FieldValue{
					&ipfix.PacketDeltaCount{Val: dCnt},
					&ipfix.SRHActiveSegmentIPv6{Val: actSeg},
					&ipfix.SRHSegmentsIPv6Left{Val: probeData.SegmentsLeft},
					&ipfix.SRHFlagsIPv6{Val: probeData.Flags},
					&ipfix.SRHTagIPv6{Val: probeData.Tag},
					&ipfix.SRHSegmentIPv6BasicList{
						SegmentList: sl,
					},
				}
				
				log.Print("test4")
				log.Print(f)

				//  Throw to channel
				flowChan <- f

				// Stats (e.g., DelayMean) are based on packets received over a fixed duration
				// These need to be cleared out for the next calculation of statistics
				delete(m.statsMap.Db, probeData)
			}
			m.statsMap.Mu.Unlock()
		}
	}

	return nil
}

func (m *Converter) Close() error {
	if err := m.xdp.Close(); err != nil {
		return err
	}

	return nil
}

func getSystemBootTime() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}
