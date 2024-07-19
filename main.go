package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I./headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpRuleMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb       strings.Builder
		src_pair struct {
			IpSrc   uint32
			PortSrc uint16
			_       [2]byte
		}
		dest_pair struct {
			IpDest   uint32
			PortDest uint16
			_        [2]byte
		}
	)
	iter := m.Iterate()
	for iter.Next(&src_pair, &dest_pair) {
		sourceIP := src_pair.IpSrc
		sourcePort := src_pair.PortSrc
		destIP := dest_pair.IpDest
		destPort := dest_pair.PortDest
		sip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(sip, sourceIP)
		dip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(dip, destIP)
		sb.WriteString(fmt.Sprintf("\t%s:%d => %s:%d\n", sip, sourcePort, dip, destPort))
	}
	return sb.String(), iter.Err()
}
