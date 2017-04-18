package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/dsnet/golib/strconv"
)

var packetChan chan packetLog

func init() {
	packetChan = make(chan packetLog, 1024)
	go logger()
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

// logPacket logs the packet for periodic printing of aggregated statistics.
func logPacket(b []byte, d direction, dropped bool) {
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
	packetChan <- p
}

func logger() {
	type packetCount struct {
		count uint64
		sizes uint64
	}

	m := map[packetLog]packetCount{}
	tc := time.Tick(30 * time.Second)
	last := time.Now().Round(time.Second)
	for {
		select {
		case p := <-packetChan:
			size := p.length
			p.length = 0
			pc := m[p]
			pc.count++
			pc.sizes += uint64(size)
			m[p] = pc
		case <-tc:
			// Skip printing statistics if traffic is low.
			var count, sizes uint64
			for _, v := range m {
				count += v.count
				sizes += v.sizes
			}
			if len(m) == 0 || (count < (1<<12) && sizes < (1<<18) && time.Now().Sub(last) < time.Hour) {
				continue
			}

			// Print an aggregated summary of all packets.
			var stats []string
			for k, v := range m {
				var proto string
				switch k.ipProtocol {
				case icmp:
					proto = "ICMP"
				case udp:
					proto = "UDP"
				case tcp:
					proto = "TCP"
				default:
					proto = fmt.Sprintf("Unknown%d", k.ipProtocol)
				}
				var drop string
				if k.dropped {
					drop = "dropped "
				}
				ipv4tos := func(ip [4]byte) string {
					return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
				}
				link := fmt.Sprintf("%s:%d -> %s:%d", ipv4tos(k.srcAddr), k.srcPort, ipv4tos(k.dstAddr), k.dstPort)
				if k.ipProtocol != tcp && k.ipProtocol != udp {
					link = fmt.Sprintf("%s -> %s", ipv4tos(k.srcAddr), ipv4tos(k.dstAddr))
				}
				sizes := strconv.FormatPrefix(float64(v.sizes), strconv.IEC, 2)
				sizes = strings.TrimSuffix(strings.TrimRight(sizes, "0"), ".")
				stats = append(stats, fmt.Sprintf("\tIPv%d/%s %s - %cx %d %spackets (%sB)",
					k.ipVersion, proto, link, k.direction, v.count, drop, sizes))
			}
			sort.Strings(stats)
			period := time.Now().Round(time.Second).Sub(last)
			log.Printf("Packet statistics (%v):\n%s", period, strings.Join(stats, "\n"))
			m = map[packetLog]packetCount{}
			last = time.Now().Round(time.Second)
		}
	}
}
