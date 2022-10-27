package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/lithDevv/gocolor"
)

var (
	InterfaceName = ""
	Found         = false
	Filter        = "tcp and port 443"
)

func sniff() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(gocolor.Red("[ERROR] Unable to find all devices") + gocolor.Blank())
	}

	for _, ifDev := range devices {
		if ifDev.Name == InterfaceName {
			Found = true
		}
	}

	if !Found {
		fmt.Println(gocolor.Red("[ERROR] Device not found") + gocolor.Blank())
		return
	}

	handle, err := pcap.OpenLive(InterfaceName, 1600, false, pcap.BlockForever)

	defer handle.Close()

	if err != nil {
		fmt.Println(gocolor.Red("[ERROR] Unable to open handle on the device") + gocolor.Blank())
		return
	}

	if err := handle.SetBPFFilter(Filter); err != nil {
		fmt.Println(gocolor.Red("[ERROR] ") + err.Error() + gocolor.Blank())
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packets := range source.Packets() {
		fmt.Println(gocolor.Green("[PACKET] ")+gocolor.Blank(), gocolor.Purple(""), packets)
	}
}

func main() {
	sniff()
}
