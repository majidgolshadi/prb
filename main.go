package main

import (
	"github.com/BurntSushi/toml"
	"github.com/majidgolshadi/eir-probe/traffic_analyzer"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"
	"time"
)

type config struct {
	ActiveNodeIp        string        `toml:"active_node_ip"`
	NetworkInterface    string        `toml:"network_interface"`
	AnalyzingBufferSize int           `toml:"analyzing_buffer_size"`
	DumpDirectory       string        `toml:"dump_dir"`
	ReportDuration      time.Duration `toml:"report_duration"`
	RedisAdd            string        `toml:"redis_add"`
	DebugPort           string        `toml:"debug_port"`

	Log Log
}

type Log struct {
	Format   string `toml:"format"`
	LogLevel string `toml:"log_level"`
	LogPoint string `toml:"log_point"`
}

func main() {
	var cnf config
	var err error

	if _, err = toml.DecodeFile("config.toml", &cnf); err != nil {
		log.Fatal("read configuration file error ", err.Error())
	}

	initLogService(cnf.Log)

	go func() {
		log.Info("debugging server listening on port ", cnf.DebugPort)
		log.Println(http.ListenAndServe(cnf.DebugPort, nil))
	}()

	sniffer, _ := traffic_analyzer.NewSniffer(
		&traffic_analyzer.SnifferOpt{
			ChanBufferSize:   cnf.AnalyzingBufferSize,
			NetworkInterface: cnf.NetworkInterface,
			DumpDirectory:    cnf.DumpDirectory,
			RedisAdd:         cnf.RedisAdd,
			ReportDuration:   cnf.ReportDuration,
			ActiveNodeIp:     strings.Split(cnf.ActiveNodeIp, ","),
		})

	sniffer.Run()
}

func initLogService(logConfig Log) {
	switch logConfig.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.WarnLevel)
	}

	switch logConfig.Format {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	default:
		break
	}

	if logConfig.LogPoint != "" {
		f, err := os.Create(logConfig.LogPoint)
		if err != nil {
			log.Fatal("create log file error: ", err.Error())
		}

		log.SetOutput(f)
	}
}
