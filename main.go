package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
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
	Ip               netip.Addr
	FailedCount      int
	TotalFailedCount int
	StartTime        time.Time
	UpdateTime       time.Time
	TimeUnit         time.Duration
}

var configFlag string

func init() {
	flag.StringVar(&configFlag, "c", "conf.toml", "config file")
}

func main() {
	flag.Parse()
	cfg := ReadConfig(configFlag)

	iface, err := net.InterfaceByName(cfg.NetIface)
	if err != nil {
		log.Fatalf("Lookup network iface %q: %s", iface, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %s", err)
	}
	defer objs.Close()

	if !cfg.BuildDictOnly {
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
	}

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

	var unlockChannel chan netip.Addr
	if !cfg.BuildDictOnly {
		// Print xdp_packet_count map
		ticker := time.NewTicker(cfg.ReportPeriod)
		defer ticker.Stop()
		go func() {
			for range ticker.C {
				s, err := formatMapContents(objs.XdpPacketCount)
				if err != nil {
					log.Printf("Error reading map: %s", err)
					continue
				}
				log.Printf("Report XDP Status: [%s]\n", s)
			}
		}()

		// Delete xdp maps
		unlockChannel = make(chan netip.Addr)
		go func() {
			for {
				incoming := <-unlockChannel
				err = objs.XdpPacketCount.Delete(incoming)
				if err != nil {
					log.Printf("Error puting xdp maps: %s", err)
				}
				log.Printf("Unlock: %s", incoming)
			}
		}()
	}

	BlockRlueMap := make(map[string]*BlockRule)
	Pd := NewPasswdDict(cfg.Users)
	defer Pd.Close()
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
		ipAddr, err := netip.ParseAddr(ipStr)
		if err != nil {
			log.Printf("Parsing ip addr: %s", err)
		}
		username := unix.ByteSliceToString(event.Username[:])
		password := unix.ByteSliceToString(event.Password[:])
		authResult := event.Result

		if cfg.BuildDictOnly {
			log.Printf(
				"Perf event value: Pid %d Comm %s, User %s Auth from %s Returns %d",
				event.Pid, unix.ByteSliceToString(event.Comm[:]),
				unix.ByteSliceToString(event.Username[:]),
				ipStr, authResult,
			)
			if authResult > 0 {
				Pd.WritePair(username, password)
			}
		} else {
			// Put xdp maps
			if rule, ok := BlockRlueMap[ipStr]; ok {
				if authResult > 0 {
					rule.FailedCount += 1
					rule.UpdateTime = time.Now()
					Pd.WritePair(username, password)
				}
				if rule.FailedCount >= cfg.MaxFailedCount {
					err = objs.XdpPacketCount.Put(ipAddr, uint32(0))
					if err != nil {
						log.Printf("Error puting xdp maps: %s", err)
					}
					log.Printf("Block: %s", ipAddr)
					// wait for unlock
					go rule.WaitUnlock(unlockChannel)
				}
			} else {
				failedCount := 0
				if authResult > 0 {
					failedCount = 1
					Pd.WritePair(username, password)
				}
				rule = &BlockRule{
					Ip:               ipAddr,
					TotalFailedCount: 0,
					FailedCount:      failedCount,
					StartTime:        time.Now(),
					UpdateTime:       time.Now(),
					TimeUnit:         cfg.TimeUnit,
				}
				BlockRlueMap[ipStr] = rule
			}
		}
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
		sb.WriteString(fmt.Sprintf("\n\t{\"Ip\": \"%s\", \"Count\": %d},", sourceIP, packetCount))
	}
	if sb.Len() > 0 {
		sb.WriteString("\n")
	}
	return sb.String(), iter.Err()
}

func (r *BlockRule) WaitUnlock(channel chan netip.Addr) {
	scale := r.TotalFailedCount
	if scale == 0 {
		scale = 1
	}
	timeout := time.Duration(scale) * r.TimeUnit
	log.Printf("Ip %s will Unlock in %s", r.Ip, r.UpdateTime.Add(timeout).Format("2006-01-02 15:04:05 MST"))
	timer := time.NewTimer(timeout)
	select {
	case <-timer.C:
		channel <- r.Ip
	}
	timer.Stop()
	r.TotalFailedCount += r.FailedCount
	r.FailedCount = 0
}
