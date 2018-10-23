package traffic_analyzer

import (
	"encoding/json"
	"github.com/go-redis/redis"
	redigo "github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"
)

type reportMaker struct {
	Statistics      map[string]*Report
	report      map[string]*Report
	calculationFlag bool

	redigoRedisConn redigo.Conn
	redisClient     *redis.Client

	reportTicker *time.Ticker
	opt          *ReportMakerOption
}

type ReportMakerOption struct {
	RedisAdd  string
	ReportSec time.Duration
}

type Report struct {
	Max     float64
	Min     float64
	Avg     float64
	Req     int
	Res     int
	MissReq int
	NotRes  int
}

type PacketInfo struct {
	Key        string
	Type       string
	IsRequest  bool
	PacketTime float64
}

const TOTAL = "total"

func NewReportMaker(option *ReportMakerOption) *reportMaker {
	rc, err := redigo.Dial("tcp", option.RedisAdd)
	if err != nil {
		log.Error("make reporter error: ", err.Error())
		return nil
	}

	rm := &reportMaker{
		Statistics:      make(map[string]*Report),
		report:      make(map[string]*Report),
		redigoRedisConn: rc,
		redisClient: redis.NewClient(&redis.Options{
			Addr:     option.RedisAdd,
			Password: "",
			DB:       0,
		}),
		opt: option,
	}

	rm.Statistics[TOTAL] = &Report{
		Min: 5000,
	}

	return rm
}

func (rm *reportMaker) Register(key string) {
	rm.Statistics[key] = &Report{
		Min: 5000,
	}

	log.Debug("type %s registered", key)
}

func (rm *reportMaker) Listen(analyzedPacket chan *PacketInfo) {
	// Activate redis event on key TTL arrived
	rm.redisClient.ConfigSet("notify-keyspace-events", "KEA")
	go rm.makeReportOnTime()
	go rm.listenOnExpiredKeys()

	for packet := range analyzedPacket {
		if packet.IsRequest {
			rm.Statistics[TOTAL].Req++
			rm.Statistics[packet.Type].Req++

			rm.redisClient.Set(makeRedisKey(packet.Type, packet.Key), packet.PacketTime, 2*time.Second)
			continue
		}

		go func(packet *PacketInfo) {
			result, _ := rm.redisClient.Get(makeRedisKey(packet.Type, packet.Key)).Result()
			if result == "" {
				rm.Statistics[TOTAL].MissReq++
				rm.Statistics[packet.Type].MissReq++
				return
			}

			rm.Statistics[TOTAL].Res++
			rm.Statistics[packet.Type].Res++

			rm.redisClient.Del(makeRedisKey(packet.Type, packet.Key))
			reqTime, _ := strconv.ParseFloat(result, 64)
			rm.calculateResponseTime(reqTime, packet)
		}(packet)
	}

}

func (rm *reportMaker) listenOnExpiredKeys() {
	psc := redigo.PubSubConn{Conn: rm.redigoRedisConn}
	psc.PSubscribe("__keyevent@*__:expired")
	for {
		switch msg := psc.Receive().(type) {
		case redigo.Message:
			if strings.Contains(string(msg.Data), "dia") {
				rm.Statistics["dia"].NotRes++
			} else {
				rm.Statistics["gsm_map"].NotRes++
			}
			rm.Statistics[TOTAL].NotRes++
		case error:
			log.Error("report maker event error: ", msg)
		}
	}
}

func makeRedisKey(packetType string, key string) string {
	return packetType + "_" + key
}

func (rm *reportMaker) makeReportOnTime() {
	rm.reportTicker = time.NewTicker(rm.opt.ReportSec * time.Second)
	for {
		<-rm.reportTicker.C
		res, err := json.Marshal(rm)

		if err != nil {
			println(err.Error())
		} else {
			println(string(res))
		}
	}
}

func (rm *reportMaker) calculateResponseTime(reqTime float64, packet *PacketInfo) {
	resTime := packet.PacketTime - reqTime

	if resTime < rm.Statistics[packet.Type].Min {
		rm.Statistics[packet.Type].Min = resTime
		rm.Statistics[TOTAL].Min = resTime
	}

	if resTime > rm.Statistics[packet.Type].Max {
		rm.Statistics[packet.Type].Max = resTime
		rm.Statistics[TOTAL].Max = resTime
	}

	rm.Statistics[packet.Type].Avg = rm.Statistics[packet.Type].Avg + ((resTime - rm.Statistics[packet.Type].Avg) / float64(rm.Statistics[packet.Type].Res))
	rm.Statistics[TOTAL].Avg = rm.Statistics[TOTAL].Avg + ((resTime - rm.Statistics[TOTAL].Avg) / float64(rm.Statistics[TOTAL].Res))
}

func (rm *reportMaker) Close() {
	log.Warn("report maker stop")

	rm.reportTicker.Stop()

	rm.redisClient.Close()
	rm.redigoRedisConn.Close()
}
