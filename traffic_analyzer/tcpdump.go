package traffic_analyzer

import (
	"os/exec"
)

type Tcpdump struct {
	FileSize    string
	createdFile map[string]int
}

func (tcpdump *Tcpdump) DumpNetworkInterfaceTrafficOn(NetworkInterface string, endpointDir string) {
	tcpdump.createdFile = make(map[string]int)
	if tcpdump.FileSize == "" {
		tcpdump.FileSize = "10mb"
	}

	_,err := exec.Command("tcpdump", "-i", NetworkInterface, "-B", "32768", "-C", tcpdump.FileSize, "-w", endpointDir+"/dump.pcap").CombinedOutput()
	if err != nil {
		//log.Fatal("tcpdump error: ", err.Error())
	}
}

func (tcpdump *Tcpdump) setFileUsers(fileAdd string, users int) {
	tcpdump.createdFile[fileAdd] = users
}

func (tcpdump *Tcpdump) fileGc(fileAdd string) {
	tcpdump.createdFile[fileAdd]--

	if tcpdump.createdFile[fileAdd] == 0 {
		exec.Command("rm", "-f", fileAdd).Run()
	}
}
