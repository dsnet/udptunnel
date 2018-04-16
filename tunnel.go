// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"net"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"
)

type direction byte

const (
	outbound direction = 'T' // Transmit
	inbound  direction = 'R' // Receive
)

type logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}

type tunnel struct {
	server        bool
	tunDevName    string
	tunLocalAddr  string
	tunRemoteAddr string
	netAddr       string
	ports         []uint16
	magic         string
	beatInterval  time.Duration

	log logger

	// remoteAddr is the address of the remote endpoint and may be
	// arbitrarily updated.
	remoteAddr atomic.Value

	// testReady and testDrop are used by tests to detect specific events.
	testReady chan<- struct{} // Closed when tunnel is ready
	testDrop  chan<- []byte   // Copy of every dropped packet
}

// run starts the VPN tunnel over UDP using the provided config and logger.
// When the context is canceled, the function is guaranteed to block until
// it is fully shutdown.
//
// The channels testReady and testDrop are only used for testing and may be nil.
func (t tunnel) run(ctx context.Context) {
	// Determine the daemon mode from the network address.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Create a new tunnel device (requires root privileges).
	conf := water.Config{DeviceType: water.TUN}
	if runtime.GOOS == "linux" && t.tunDevName != "" {
		// Use reflect to avoid separate build file for linux-only.
		reflect.ValueOf(&conf).Elem().FieldByName("Name").SetString(t.tunDevName)
	}
	iface, err := water.New(conf)
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	t.log.Printf("created tun device: %v", iface.Name())
	defer iface.Close()
	defer pingIface(t.tunLocalAddr)

	// Setup IP properties.
	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("/sbin/ip", "link", "set", "dev", iface.Name(), "mtu", "1300").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
		if err := exec.Command("/sbin/ip", "addr", "add", t.tunLocalAddr+"/24", "dev", iface.Name()).Run(); err != nil {
			t.log.Fatalf("ip addr error: %v", err)
		}
		if err := exec.Command("/sbin/ip", "link", "set", "dev", iface.Name(), "up").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
	case "darwin":
		if err := exec.Command("/sbin/ifconfig", iface.Name(), "mtu", "1300", t.tunLocalAddr, t.tunRemoteAddr, "up").Run(); err != nil {
			t.log.Fatalf("ifconfig error: %v", err)
		}
	default:
		t.log.Fatalf("no tun support for: %v", runtime.GOOS)
	}

	// Create a new UDP socket.
	_, port, _ := net.SplitHostPort(t.netAddr)
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("", port))
	if err != nil {
		t.log.Fatalf("error resolving address: %v", err)
	}
	sock, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.log.Fatalf("error listening on socket: %v", err)
	}
	defer sock.Close()

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435

	if t.testReady != nil {
		close(t.testReady)
	}
	pf := newPortFilter(t.ports)
	pl := newPacketLogger(ctx, &wg, t.log)

	// On the client, start some goroutines to accommodate for the dynamically
	// changing environment that the client may be in.
	magic := md5.Sum([]byte(t.magic))
	if !t.server {
		// Since the remote address could change due to updates to DNS,
		// periodically check DNS for a new address.
		raddr, err := net.ResolveUDPAddr("udp", t.netAddr)
		if err != nil {
			t.log.Fatalf("error resolving address: %v", err)
		}
		t.updateRemoteAddr(raddr)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				raddr, _ := net.ResolveUDPAddr("udp", t.netAddr)
				if isDone(ctx) {
					return
				}
				t.updateRemoteAddr(raddr)
			}
		}()

		// Since the local address could change due to switching interfaces
		// (e.g., switching from cellular hotspot to hardwire ethernet),
		// periodically ping the server to inform it of our new UDP address.
		// Sending a packet with only the magic header is sufficient.
		go func() {
			if t.beatInterval == 0 {
				return
			}
			ticker := time.NewTicker(t.beatInterval)
			defer ticker.Stop()
			var prevTxn uint64
			for range ticker.C {
				if isDone(ctx) { // Stop if done.
					return
				}
				raddr := t.loadRemoteAddr()
				if raddr == nil { // Skip if no remote endpoint.
					continue
				}
				txn := pl.Stats().Tx.Okay.Count
				if prevTxn == txn { // Only send if there is no outbound traffic
					sock.WriteToUDP(magic[:], raddr)
				}
				prevTxn = txn
			}
		}()
	}

	// Handle outbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, err := iface.Read(b[len(magic):])
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun read error: %v", err)
			}
			n += copy(b, magic[:])
			p := b[len(magic):n]

			raddr := t.loadRemoteAddr()
			if pf.Filter(p, outbound) || raddr == nil {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, outbound, true)
				continue
			}

			if _, err := sock.WriteToUDP(b[:n], raddr); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net write error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			pl.Log(p, outbound, false)
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		for {
			n, raddr, err := sock.ReadFromUDP(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net read error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			if !bytes.HasPrefix(b[:n], magic[:]) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), b[:n]...)
				}
				t.log.Printf("invalid packet from remote address: %v", raddr)
				continue
			}
			p := b[len(magic):n]

			// We assume a matching magic prefix is sufficient to validate
			// that the new IP is really the remote endpoint.
			// We assume that any adversary capable of performing a replay
			// attack already has the power to disrupt communication.
			if t.server {
				t.updateRemoteAddr(raddr)
			}
			if len(p) == 0 {
				continue // Assume empty packets are a form of pinging
			}

			if pf.Filter(p, inbound) {
				if t.testDrop != nil {
					t.testDrop <- append([]byte(nil), p...)
				}
				pl.Log(p, inbound, true)
				continue
			}

			if _, err := iface.Write(p); err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun write error: %v", err)
			}
			pl.Log(p, inbound, false)
		}
	}()

	<-ctx.Done()
}

func (t *tunnel) loadRemoteAddr() *net.UDPAddr {
	addr, _ := t.remoteAddr.Load().(*net.UDPAddr)
	return addr
}
func (t *tunnel) updateRemoteAddr(addr *net.UDPAddr) {
	oldAddr := t.loadRemoteAddr()
	if addr != nil && (oldAddr == nil || !addr.IP.Equal(oldAddr.IP) || addr.Port != oldAddr.Port || addr.Zone != oldAddr.Zone) {
		t.remoteAddr.Store(addr)
		t.log.Printf("switching remote address: %v", addr)
	}
}

// pingIface sends a broadcast ping to the IP range of the TUN device
// until the TUN device has shutdown.
func pingIface(addr string) {
	// HACK(dsnet): For reasons I do not understand, closing the TUN device
	// does not cause a pending Read operation to become unblocked and return
	// with some EOF error. As a workaround, we broadcast on the IP range
	// of the TUN device, forcing the Read to unblock with at least one packet.
	// The subsequent call to Read will properly report that it is closed.
	//
	// See https://github.com/songgao/water/issues/22
	go func() {
		addr = strings.TrimRight(addr, "0123456798")
		for i := 0; i < 256; i++ {
			cmd := exec.Command("ping", "-c", "1", addr+strconv.Itoa(i))
			cmd.Start()
		}
	}()
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
