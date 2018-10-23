package traffic_analyzer

import (
	"errors"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"time"
)

type SnifferOpt struct {
	DumpDirectory    string
	RedisAdd         string
	ReportDuration   time.Duration
	ActiveNodeIp     []string
	ChanBufferSize   int
	NetworkInterface string
}

type sniffer struct {
	opt *SnifferOpt
}

func NewSniffer(opt *SnifferOpt) (*sniffer, error) {
	if opt.DumpDirectory == "" {
		return nil, errors.New("tcpdump dump directory does not set")
	}

	if len(opt.ActiveNodeIp) == 0 {
		return nil, errors.New("active node ip does not set")
	}

	if opt.NetworkInterface == "" {
		return nil, errors.New("choose which interface to listen on")
	}

	if opt.RedisAdd == "" {
		opt.RedisAdd = "127.0.0.1:6379"
	}

	if opt.ReportDuration == 0 {
		opt.ReportDuration = 10
	}

	if opt.ChanBufferSize == 0 {
		opt.ChanBufferSize = 100
	}

	return &sniffer{
		opt: opt,
	}, nil
}

func (sniffer *sniffer) Run() error {
	chPacketInfo := make(chan *PacketInfo, sniffer.opt.ChanBufferSize)
	tcpdumper := &Tcpdump{}
	reporter := NewReportMaker(&ReportMakerOption{
		RedisAdd:  sniffer.opt.RedisAdd,
		ReportSec: sniffer.opt.ReportDuration,
	})

	dia := NewDiameterAnalyzer(reporter, sniffer.opt.ActiveNodeIp, chPacketInfo)
	gsm := NewGsmMapAnalyzer(reporter, sniffer.opt.ActiveNodeIp, chPacketInfo)

	go reporter.Listen(chPacketInfo)
	go tcpdumper.DumpNetworkInterfaceTrafficOn(sniffer.opt.NetworkInterface, sniffer.opt.DumpDirectory)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op.String() == "CREATE" {
					tcpdumper.setFileUsers(event.Name, 2)
					go dia.AnalyzeOn(event.Name, tcpdumper)
					go gsm.analyzeOn(event.Name, tcpdumper)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error("sniffer error: ", err.Error())
			}
		}
	}()

	err = watcher.Add(sniffer.opt.DumpDirectory)
	if err != nil {
		return err
	}
	<-done

	return nil
}
