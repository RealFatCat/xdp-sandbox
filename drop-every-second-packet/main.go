//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	pageSize        = 4096
	eventStructSize = 12
)

type eventType uint8

const (
	unknownEvent eventType = iota
	enterEvent
	dropEvent
	passEvent
)

var events = make(map[eventType]uint32, 3)

type event struct {
	timeSinceBoot  uint64
	processingTime uint32
	eType          eventType
}

var ifaceName string

func init() {
	flag.StringVar(&ifaceName, "iface", "enp3s0", "interface to attach xdp program")
	flag.Parse()
}

func main() {
	var objs dropObjects

	// Load the compiled eBPF ELF and upload it into the kernel.
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifaceName, err)
	}

	// Attach program to the network interface.
	link, err := link.AttachXDP(
		link.XDPOptions{
			Program:   objs.XdpDrops2nd,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		},
	)
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Dropping packets on packets on %s", iface.Name)

	// Create perf event reader
	perfEvent, err := perf.NewReader(objs.PerfMap, pageSize)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v\n", err)
	}
	defer perfEvent.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)

	rbPass := newProcTimeRingBuffer(64)
	rbDrop := newProcTimeRingBuffer(64)

	// Run perf event reader
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := perfEvent.Read()
			if err != nil {
				log.Println(err)
				continue
			}

			if len(record.RawSample) < eventStructSize {
				log.Println("Invalid sample size")
				continue
			}

			var evnt event
			evnt.timeSinceBoot = binary.LittleEndian.Uint64(record.RawSample[:8])    // read first 8 bytes
			evnt.processingTime = binary.LittleEndian.Uint32(record.RawSample[8:12]) // than next 4 bytes
			evnt.eType = eventType(record.RawSample[12])                             // than the last one byte
			events[evnt.eType]++

			_ = evnt.timeSinceBoot // we don't use this value anywhere in this code (but in C), and fill this field just for demonstration

			switch evnt.eType {
			case passEvent:
				rbPass.Add(evnt.processingTime)
			case dropEvent:
				rbDrop.Add(evnt.processingTime)
			default:
			}
		}
	}()

	// Print info with results
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	go func() {
		defer wg.Done()

		for {
			select {
			case <-ticker.C:
				log.Printf(`total packets: %d; passed: %d; dropped: %d; passed p50: %s, p95: %s; dropped p50: %s, p95: %s;`,
					events[enterEvent],
					events[passEvent],
					events[dropEvent],
					time.Duration(rbPass.Perc(0.5)),
					time.Duration(rbPass.Perc(0.95)),
					time.Duration(rbDrop.Perc(0.5)),
					time.Duration(rbDrop.Perc(0.95)),
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
}
