package traffic_analyzer

import (
	"encoding/json"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
	"time"
)

type reportMaker struct {
	Statistics      map[string]*Report
	report          map[string]*Report
	calculationFlag bool

	mainCache *cache.Cache
	missCache *cache.Cache

	reportTicker *time.Ticker
	opt          *ReportMakerOption
}

type ReportMakerOption struct {
	ReportSec         time.Duration
	ReqTtlSec         time.Duration
	ReqCleanupSec     time.Duration
	MissTtlSec        time.Duration
	MissTtlCleanupSec time.Duration
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

func NewReportMaker(opt *ReportMakerOption) *reportMaker {

	mainCache := cache.New(opt.ReqTtlSec*time.Second, opt.ReqCleanupSec*time.Second)
	missCache := cache.New(opt.MissTtlSec*time.Second, opt.MissTtlCleanupSec*time.Second)

	rm := &reportMaker{
		Statistics: make(map[string]*Report),
		report:     make(map[string]*Report),
		mainCache:  mainCache,
		missCache:  missCache,
		opt:        opt,
	}

	rm.Statistics[TOTAL] = &Report{
		Min: 5000,
	}

	return rm
}

func (rm *reportMaker) onMainCacheEvicted(key string, value interface{}) {
	_, exist := rm.missCache.Get(key)
	if exist {
		rm.missCache.Delete(key)
		return
	}

	rm.Statistics[TOTAL].NotRes++
	rm.Statistics[getTypeFromKey(key)].Res++

	rm.missCache.Set(key, value, cache.DefaultExpiration)
}

func (rm *reportMaker) Register(key string) {
	rm.Statistics[key] = &Report{
		Min: 5000,
	}

	log.Debug("type %s registered", key)
}

func (rm *reportMaker) Listen(analyzedPacket chan *PacketInfo) {
	go rm.makeReportOnTime()
	rm.mainCache.OnEvicted(rm.onMainCacheEvicted)

	for packet := range analyzedPacket {
		if packet.IsRequest {
			rm.Statistics[TOTAL].Req++
			rm.Statistics[packet.Type].Req++
		} else {
			rm.Statistics[TOTAL].Res++
			rm.Statistics[packet.Type].Res++
		}

		go func(packet *PacketInfo) {
			result, exist := rm.mainCache.Get(makeKey(packet.Type, packet.Key))
			if !exist {
				rm.mainCache.Set(makeKey(packet.Type, packet.Key), packet.PacketTime, cache.DefaultExpiration)
				return
			}

			rm.mainCache.Delete(makeKey(packet.Type, packet.Key))
			reqTime, _ := strconv.ParseFloat(result.(string), 64)
			rm.calculateResponseTime(reqTime, packet)
		}(packet)
	}

}

func makeKey(packetType string, key string) string {
	return packetType + "_" + key
}

func getTypeFromKey(key string) string {
	return strings.Split(key, "_")[0]
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
}
