package traffic_analyzer

import (
	"github.com/ionrock/procs"
	"strconv"

	"encoding/json"
)

type diameterAnalyzer struct {
	reporter               *reportMaker
	activeNodeIp           []string
	analyzedPacketInfoChan chan *PacketInfo
	processList            map[string]*procs.Process
}

type DiameterTsharkJson struct {
	Layers struct {
		IPSrc             []string `json:"ip_src"`
		DiameterSessionID []string `json:"diameter_Session-Id"`
		FrameTimeEpoch    []string `json:"frame_time_epoch"`
		DiameterCmdCode   []string `json:"diameter_cmd_code"`
	} `json:"layers"`
}

func NewDiameterAnalyzer(reporter *reportMaker, activeNodeIp []string, analyzedPacketInfoChan chan *PacketInfo) *diameterAnalyzer {
	analyzer := &diameterAnalyzer{
		processList:            make(map[string]*procs.Process),
		reporter:               reporter,
		activeNodeIp:           activeNodeIp,
		analyzedPacketInfoChan: analyzedPacketInfoChan,
	}

	reporter.Register(analyzer.getType())

	return analyzer
}

func (analyzer *diameterAnalyzer) AnalyzeOn(fileAbsolutePath string, tcpdump *Tcpdump) {
	var (
		isRequest bool
		epochTime float64
		err       error
	)

	p := procs.NewProcess("tshark -r " + fileAbsolutePath + ` -Y diameter -T ek -e ip.src -e diameter.Session-Id -e frame.time_epoch -e diameter.cmd.code | grep timestamp`)
	analyzer.processList[fileAbsolutePath] = p

	p.OutputHandler = func(line string) string {
		tsharkData := &DiameterTsharkJson{}
		err := json.Unmarshal([]byte(line), tsharkData)
		if err != nil {
			println(err.Error())
		}

		if tsharkData.Layers.DiameterCmdCode[0] != "324" {
			return line
		}

		isRequest = func(srcIp string) bool {
			for _, ip := range analyzer.activeNodeIp {
				if srcIp == ip {
					return false
				}
			}

			return true
		}(tsharkData.Layers.IPSrc[0])

		epochTime, err = strconv.ParseFloat(tsharkData.Layers.FrameTimeEpoch[0], 64)
		if err != nil {
			print(err.Error())
			return line
		}

		for _, reqKey := range tsharkData.Layers.DiameterSessionID {
			analyzer.analyzedPacketInfoChan <- &PacketInfo{
				Type:       analyzer.getType(),
				IsRequest:  isRequest,
				PacketTime: epochTime,
				Key:        reqKey,
			}
		}

		return line
	}

	err = p.Run()
	delete(analyzer.processList, fileAbsolutePath)
	//tcpdump.fileGc(fileAbsolutePath)
	if err != nil {
		return
	}
}

func (analyzer *diameterAnalyzer) getType() string {
	return "dia"
}
