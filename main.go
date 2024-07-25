package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf xdp.c -- -I./headers

type BlockRule struct {
	Ip          netip.Addr
	FailedCount int
	StartTime   time.Time
	UpdateTime  time.Time
	Scale       time.Duration
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the XDP program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgMain,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

	// Uprobe PAM lib.
	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libpam.so.0")
	if err != nil {
		log.Fatalf("Opening executable: %s", err)
	}

	up, err := ex.Uprobe("pam_get_authtok", objs.UprobePamGetAuthtok, nil)
	if err != nil {
		log.Fatalf("Creating uprobe for pam_get_authtok: %s", err)
	}
	defer up.Close()

	urp, err := ex.Uretprobe("pam_get_authtok", objs.UretprobePamGetAuthtok, nil)
	if err != nil {
		log.Fatalf("Creating uretprobe for pam_get_authtok: %s", err)
	}
	defer urp.Close()

	urpAuth, err := ex.Uretprobe("pam_authenticate", objs.UretprobePamAuthenticate, nil)
	if err != nil {
		log.Fatalf("Creating uretprobe for pam_authenticate: %s", err)
	}
	defer urpAuth.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	// Run stopper.
	log.Printf("Press Ctrl-C to exit and remove the program")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("Closing perf event reader: %s", err)
		}
	}()

	// Print xdp_packet_count map
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			s, err := formatMapContents(objs.XdpPacketCount)
			if err != nil {
				log.Printf("Error reading map: %s", err)
				continue
			}
			log.Printf("%s\n", s)
		}
	}()

	BlockRlueMap := make(map[string]*BlockRule)
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Parsing perf event: %s", err)
			continue
		}
		ipStr := unix.ByteSliceToString(event.Rhost[:])
		authResult := event.Result
		if rule, ok := BlockRlueMap[ipStr]; ok {
			if authResult > 0 {
				rule.FailedCount += 1
			}
			if rule.FailedCount >= 3 {
				ipAddr, err := netip.ParseAddr(ipStr)
				if err != nil {
					log.Printf("Parsing ip addr: %s", err)
				}
				err = objs.XdpPacketCount.Put(ipAddr, uint32(0))
				if err != nil {
					log.Printf("Put map %s", err)
				}
			}
			log.Printf("%v", rule)
		} else {
			ipAddr, err := netip.ParseAddr(ipStr)
			if err != nil {
				log.Printf("Parsing ip addr: %s", err)
			}
			failedCount := 0
			if authResult > 0 {
				failedCount = 1
			}
			rule = &BlockRule{
				Ip:          ipAddr,
				FailedCount: failedCount,
				StartTime:   time.Now(),
				UpdateTime:  time.Now(),
				Scale:       60 * time.Second,
			}
			BlockRlueMap[ipStr] = rule
		}
		log.Printf("Perf event value: %d,%s,%s,%s,%d", event.Pid, unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Username[:]), ipStr, authResult)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}
