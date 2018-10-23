package traffic_analyzer

import (
	"encoding/json"
	"github.com/ionrock/procs"
	"strconv"
)

type gsmMapAnalyzer struct {
	reporter               *reportMaker
	activeNodeIp           []string
	analyzedPacketInfoChan chan *PacketInfo
	processList            map[string]*procs.Process
}

type GsmMapTsharkJson struct {
	Layers struct {
		IPSrc          []string `json:"ip_src"`
		TcapInvokeID   []string `json:"tcap_invokeID"`
		TcapTid        []string `json:"tcap_tid"`
		FrameTimeEpoch []string `json:"frame_time_epoch"`
	} `json:"layers"`
}

func NewGsmMapAnalyzer(reporter *reportMaker, activeNodeIp []string, analyzedPacketInfoChan chan *PacketInfo) *gsmMapAnalyzer {
	analyzer := &gsmMapAnalyzer{
		processList:            make(map[string]*procs.Process),
		reporter:               reporter,
		activeNodeIp:           activeNodeIp,
		analyzedPacketInfoChan: analyzedPacketInfoChan,
	}

	reporter.Register(analyzer.getType())

	return analyzer
}

func (analyzer *gsmMapAnalyzer) analyzeOn(fileAbsolutePath string, tcpdump *Tcpdump) {
	var (
		isResponse bool
		epochTime  float64
		err        error
	)

	p := procs.NewProcess("tshark -r " + fileAbsolutePath + ` -Y gsm_map -T ek -e ip.src -e tcap.invokeID -e tcap.tid -e frame.time_epoch | grep timestamp`)
	analyzer.processList[fileAbsolutePath] = p

	p.OutputHandler = func(line string) string {
		tsharkData := &GsmMapTsharkJson{}
		err := json.Unmarshal([]byte(line), tsharkData)
		if err != nil {
			println(err.Error())
		}

		isResponse = func(srcIp string) bool {
			for _, ip := range analyzer.activeNodeIp {
				if srcIp == ip {
					return true
				}
			}

			return false
		}(tsharkData.Layers.IPSrc[0])

		epochTime, err = strconv.ParseFloat(tsharkData.Layers.FrameTimeEpoch[0], 64)
		if err != nil {
			print(err.Error())
			return line
		}

		for index, tcapId := range tsharkData.Layers.TcapTid {
			analyzer.analyzedPacketInfoChan <- &PacketInfo{
				Type:       analyzer.getType(),
				IsRequest:  isResponse,
				PacketTime: epochTime,
				Key:        tcapId + tsharkData.Layers.TcapInvokeID[index],
			}
		}

		return line
	}

	err = p.Run()
	delete(analyzer.processList, fileAbsolutePath)
	tcpdump.fileGc(fileAbsolutePath)
	if err != nil {
		return
	}
}

func (analyzer *gsmMapAnalyzer) getType() string {
	return "gsm_map"
}
