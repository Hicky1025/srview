package client

import (
	"net"
	"time"

	"github.com/Hicky1025/srview/pkg/ipfix"
)

func New(ingressIfName string, raddr *net.UDPAddr, interval int) ClientError {
	ch := make(chan []ipfix.FieldValue)
	errChan := make(chan ClientError)

	e := NewExporter()
	go func() {
		err := e.Run(raddr, ch)
		if err != nil {
			errChan <- ClientError{
				Component: "exporter",
				Error:     err,
			}
		}
	}()

	m := NewMeter(ingressIfName)
	go func() {
		err := m.Run(ch, time.Duration(interval))
		if err != nil {
			errChan <- ClientError{
				Component: "meter",
				Error:     err,
			}
		}
		m.Close()
	}()

	// meterとexporterはgo routineで同期
	for {
		clientError := <-errChan
		return clientError
	}
}
