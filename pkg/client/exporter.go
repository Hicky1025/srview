package client

import (
	"log"
	"net"
	"os"

	"github.com/Hicky1025/srview/pkg/ipfix"
)

const OBSERVATION_ID uint32 = 61166

type Exporter struct {
	flowSeq    uint32
	tempRecSeq uint16
}

func NewExporter() *Exporter {
	e := &Exporter{
		flowSeq:    1,
		tempRecSeq: 256,
	}
	return e
}

func (e *Exporter) Run(raddr *net.UDPAddr, flowChan chan []ipfix.FieldValue) error {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var m *ipfix.Message

	// channel経由で取得したbpfのSRv6の情報を受け取る
	for {
		fvs := <-flowChan
		var sets []ipfix.Set

		// 1. データテンプレートの作成
		var fss []ipfix.FieldSpecifier
		for _, fv := range fvs {
			fss = append(fss, *fv.FieldSpecifier())
		}
		tempRec := ipfix.NewTemplateRecord(e.tempRecSeq, fss)
		tempSet := ipfix.NewSet(ipfix.TEMPLATE_SETS_ID, []ipfix.Record{tempRec})
		sets = append(sets, *tempSet)

		// 2. データの挿入
		dataRec := &ipfix.DataRecord{FieldValues: fvs}
		dataSet := ipfix.NewSet(e.tempRecSeq, []ipfix.Record{dataRec})
		sets = append(sets, *dataSet)

		// 3. メッセージの挿入
		m = ipfix.NewMessage(e.flowSeq, OBSERVATION_ID, sets)
		e.tempRecSeq += uint16(len(tempSet.Records))
		e.flowSeq += uint32(len(dataSet.Records))

		//4. 送信
		SendMessage(m, conn)
	}
}

func SendMessage(message *ipfix.Message, conn *net.UDPConn) {
	byteMessage := message.Serialize()

	_, err := conn.Write(byteMessage)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
