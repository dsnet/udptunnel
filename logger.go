// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dsnet/golib/unitconv"
)

type packetLogger struct {
	logger logger
	last   time.Time // Last time we printed statistics
	c      chan packetLog
	m      map[packetLog]packetCount
	rx, tx struct{ okay, drop packetCount }
}

type packetLog struct {
	direction  direction
	dropped    bool
	ipVersion  int
	ipProtocol int
	srcAddr    [4]byte
	dstAddr    [4]byte
	srcPort    uint16
	dstPort    uint16
	length     int
}

type packetCount struct {
	count uint64
	sizes uint64
}

func newPacketLogger(ctx context.Context, wg *sync.WaitGroup, logger logger) *packetLogger {
	pl := &packetLogger{
		logger: logger,
		last:   time.Now().Round(time.Second),
		c:      make(chan packetLog, 1024),
		m:      make(map[packetLog]packetCount),
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		pl.monitor(ctx)
	}()
	return pl
}

// Log logs the packet for periodic printing of aggregated statistics.
func (pl *packetLogger) Log(b []byte, d direction, dropped bool) {
	ip := ipPacket(b)
	p := packetLog{
		direction:  d,
		dropped:    dropped,
		ipVersion:  ip.Version(),
		length:     len(b),
		ipProtocol: ip.Protocol(),
	}
	if p.ipVersion == 4 {
		p.srcAddr, p.dstAddr = ip.AddressesV4()
	}
	if p.ipProtocol == udp || p.ipProtocol == tcp {
		p.srcPort, p.dstPort = transportPacket(ip.Body()).Ports()
	}
	pl.c <- p
}

func (pl *packetLogger) monitor(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	for {
		select {
		case p := <-pl.c:
			size := p.length
			p.length = 0
			pc := pl.m[p]
			pc.count++
			pc.sizes += uint64(size)
			pl.m[p] = pc
		case <-t.C:
			var count, sizes uint64
			for _, v := range pl.m {
				count += v.count
				sizes += v.sizes
			}
			if count < (1<<12) && sizes < (1<<18) && time.Now().Sub(pl.last) < time.Hour {
				continue // Skip printing statistics if traffic is low.
			}
			pl.print()
		case <-ctx.Done():
			pl.print()
			return
		}
	}
}

// print prints an aggregated summary of all packets.
// To avoid races, this method is only called from monitor.
func (pl *packetLogger) print() {
	if len(pl.m) == 0 {
		return
	}
	stats := make([]string, 2) // First 2 lines for total stats
	protoNames := map[int]string{icmp: "ICMP", udp: "UDP", tcp: "TCP"}
	for k, v := range pl.m {
		var pc *packetCount
		switch {
		case !k.dropped && k.direction == outbound:
			pc = &pl.tx.okay
		case !k.dropped && k.direction == inbound:
			pc = &pl.rx.okay
		case k.dropped && k.direction == outbound:
			pc = &pl.tx.drop
		case k.dropped && k.direction == inbound:
			pc = &pl.rx.drop
		}
		pc.count += v.count
		pc.sizes += v.sizes

		proto := protoNames[k.ipProtocol]
		if proto == "" {
			proto = fmt.Sprintf("Unknown%d", k.ipProtocol)
		}
		var drop string
		if k.dropped {
			drop = "dropped "
		}
		link := fmt.Sprintf("%s:%d -> %s:%d", formatIPv4(k.srcAddr), k.srcPort, formatIPv4(k.dstAddr), k.dstPort)
		if k.ipProtocol != tcp && k.ipProtocol != udp {
			link = fmt.Sprintf("%s -> %s", formatIPv4(k.srcAddr), formatIPv4(k.dstAddr))
		}
		stats = append(stats, fmt.Sprintf("\tIPv%d/%s %s - %cx %d %spackets (%sB)",
			k.ipVersion, proto, link, k.direction, v.count, drop, formatIEC(v.sizes)))
	}
	stats[0] = fmt.Sprintf("\tRx %d total packets (%sB), dropped %d total packets (%sB)",
		pl.rx.okay.count, formatIEC(pl.rx.okay.sizes), pl.rx.drop.count, formatIEC(pl.rx.drop.sizes))
	stats[1] = fmt.Sprintf("\tTx %d total packets (%sB), dropped %d total packets (%sB)",
		pl.tx.okay.count, formatIEC(pl.tx.okay.sizes), pl.tx.drop.count, formatIEC(pl.tx.drop.sizes))
	sort.Strings(stats[2:])
	period := time.Now().Round(time.Second).Sub(pl.last)
	pl.logger.Printf("Packet statistics (%v):\n%s", period, strings.Join(stats, "\n"))
	pl.m = map[packetLog]packetCount{}
	pl.last = time.Now().Round(time.Second)
}

func formatIEC(n uint64) string {
	s := unitconv.FormatPrefix(float64(n), unitconv.IEC, 2)
	return strings.TrimSuffix(strings.TrimRight(s, "0"), ".")
}

func formatIPv4(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}
