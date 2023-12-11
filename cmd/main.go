package main

import (
	"flag"
	"log"
	"net"

	"github.com/Hicky1025/srview/pkg/config"
	"github.com/Hicky1025/srview/pkg/client"
)

type flags struct {
	configFile    string
	ingressIfName string
}

func main() {
	// 引数の定義
	f := &flags{}
	flag.StringVar(&f.configFile, "f", "srview.yaml", "Specify a configuration file")
	flag.StringVar(&f.ingressIfName, "i", "", "Specify a configuration file")
	flag.Parse()

	// コンフィグファイルの読み込み
	c, err := config.ReadConfigFile(f.configFile)
	if err != nil {
		log.Panic(err)
	}

	// 監視基盤の定義
	raddr, err := net.ResolveUDPAddr("udp", c.Ipfix.Address+":"+c.Ipfix.Port)
	if err != nil {
		log.Panic(err)
	}

	// 監視対象インターフェースの定義
	ingressIfName := f.ingressIfName
	if f.ingressIfName == "" {
		ingressIfName = c.Ipfix.IngressInterface
	}

	// 監視インターバルの定義
	interval := c.Ipfix.Interval
	if interval <= 0 {
		interval = 1
	}

	// 起動
	client.New(ingressIfName, raddr, interval)
}
