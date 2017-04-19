package main

import (
	"encoding/binary"
	"sync/atomic"
	"time"
)

// The current timestamp in seconds. Must be read using atomic operations.
var atomicNow uint64

func init() {
	atomicNow = uint64(time.Now().Unix())
	go func() {
		for range time.Tick(time.Second) {
			atomic.AddUint64(&atomicNow, 1)
		}
	}()
}

var timeNow = func() uint64 {
	return atomic.LoadUint64(&atomicNow)
}

const (
	icmp = 1
	tcp  = 6
	udp  = 17
)

type ipPacket []byte

func (ip ipPacket) Version() int {
	if len(ip) > 0 {
		return int(ip[0] >> 4)
	}
	return 0
}

func (ip ipPacket) Protocol() int {
	if len(ip) > 9 && ip.Version() == 4 {
		return int(ip[9])
	}
	return 0
}

func (ip ipPacket) AddressesV4() (src, dst [4]byte) {
	if len(ip) >= 20 && ip.Version() == 4 {
		copy(src[:], ip[12:16])
		copy(dst[:], ip[16:20])
	}
	return
}

func (ip ipPacket) Body() []byte {
	if ip.Version() != 4 {
		return nil // No support for IPv6
	}
	n := int(ip[0] & 0x0f)
	if n < 5 || n > 15 || len(ip) < 4*n {
		return nil
	}
	return ip[4*n:]
}

type transportPacket []byte

func (tp transportPacket) Ports() (src, dst uint16) {
	if len(tp) >= 4 {
		src = binary.BigEndian.Uint16(tp[:2])
		dst = binary.BigEndian.Uint16(tp[2:])
	}
	return
}

type portFilter struct {
	// Last time a packet was transmitted on some ephemeral source port.
	outMap [1 << 16]uint64 // [port]time

	// Last time a packet was received from some ephemeral source port.
	inMap [1 << 16]uint64 // [port]time

	// Set of allowed inbound ports.
	ports map[uint16]bool
}

func newPortFilter(ports []uint16) *portFilter {
	sf := &portFilter{ports: make(map[uint16]bool)}
	for _, p := range ports {
		sf.ports[p] = true
	}
	return sf
}

func (sf *portFilter) Filter(b []byte, d direction) (drop bool) {
	// This logic assumes malformed IP packets are rejected by the Linux kernel.
	ip := ipPacket(b)
	if ip.Version() != 4 {
		return true // No support for tunneling IPv6
	}
	if ip.Protocol() != tcp && ip.Protocol() != udp {
		return ip.Protocol() != icmp // Always allow ping
	}
	src, dst := transportPacket(ip.Body()).Ports()
	switch d {
	case outbound:
		if sf.ports[src] && dst > 0 {
			// Check whether the destination port is somewhere we have received
			// an inbound packet from.
			ts := atomic.LoadUint64(&sf.inMap[dst])
			return timeNow()-ts >= 3600
		}
		if sf.ports[dst] && src > 0 {
			// Allowed outbound packet, remember the source port so that inbound
			// traffic is allowed to hit that destination port.
			atomic.StoreUint64(&sf.outMap[src], timeNow())
			return false
		}
	case inbound:
		if sf.ports[src] && dst > 0 {
			// Check whether the destination port is somewhere we have sent
			// an outbound packet to.
			ts := atomic.LoadUint64(&sf.outMap[dst])
			return timeNow()-ts >= 3600
		}
		if sf.ports[dst] && src > 0 {
			// Allowed inbound packet, remember the source port so that outbound
			// traffic is allowed to hit that destination port.
			atomic.StoreUint64(&sf.inMap[src], timeNow())
			return false
		}
	}
	return true
}
