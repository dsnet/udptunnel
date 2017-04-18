// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

// udptunnel is a daemon that sets up a point-to-point virtual private network
// between two hosts:
//	* A client host that may be behind an obtrusive NAT that frequently drops
//	TCP connections, but happens to pass UDP traffic reliably.
//	* A server host that is internet-accessible.
//
// Example Setup
//
// The udptunnel is setup by running it on two different hosts, one in a server
// configuration, and the other in client configuration. The difference between
// a server or client is determined by the NetworkAddress field in the
// configuration. If the address starts with 0.0.0.0, then the daemon operates
// in server mode. Otherwise, the daemon operates in client mode and will use
// the address to dial the server.
//
// Example server config:
//	{"TunnelAddress": "10.0.0.1", "NetworkAddress": "0.0.0.0:8000", "AllowedPorts": [22]}
// Example client config:
//	{"TunnelAddress": "10.0.0.2", "NetworkAddress": "foo.com:8000", "AllowedPorts": [22]}
//
// See the TunnelConfig struct for more details.
//
// Security Considerations
//
// TUN traffic is sent ad-verbatim between the two endpoints via unencrypted
// UDP traffic. The intended use case is to run a secure protocol (like SSH;
// see github.com/dsnet/sshtunnel) on top of this simple VPN. In order to
// prevent attackers from connecting to other locally binded sockets on the
// endpoints, a simple port filter is built-in to restrict IP traffic to only
// the specified ports. Users of udptunnel should also setup iptable rules as
// a secondary measure to restrict malicious traffic.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dsnet/golib/jsonutil"
	"github.com/songgao/water"
)

type TunnelConfig struct {
	// LogFile is where the tunnel daemon will direct its output log.
	// If the path is empty, then the server will output to os.Stderr.
	LogFile string

	// TunnelDevice is the name of the TUN device (default: tunnel).
	TunnelDevice string

	// TunnelAddress is the private IP address for the tunnel (e.g., 10.0.0.1).
	// The client and server should have different IP addresses both in the
	// 255.255.255.0 subnet mask.
	TunnelAddress string

	// NetworkAddress is the public IP address and port for the tunnel.
	// If the address starts with 0.0.0.0, then the daemon is operating in
	// server mode and will bind on the specified port (e.g., 0.0.0.0:8000).
	// Otherwise, the daemon is operating in client mode and will use the
	// specified address to communicate with the server (e.g., foo.com:8000).
	NetworkAddress string

	// AllowedPorts is a list of allowed UDP and TCP ports.
	AllowedPorts []uint16
}

type direction byte

const (
	outbound direction = 'T' // Transmit
	inbound  direction = 'R' // Receive
)

func loadConfig(conf string) (config TunnelConfig, closer func() error) {
	var logBuf bytes.Buffer
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.SetOutput(io.MultiWriter(os.Stderr, &logBuf))

	// Load configuration file.
	c, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("unable to read config: %v", err)
	}
	c, _ = jsonutil.Minify(c)
	if err := json.Unmarshal(c, &config); err != nil {
		log.Fatalf("unable to decode config: %v", err)
	}
	if config.TunnelDevice == "" {
		config.TunnelDevice = "tunnel"
	}
	if len(config.AllowedPorts) == 0 {
		log.Fatalf("no allowed ports specified")
	}

	// Print the configuration.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	enc.Encode(&config)
	log.Printf("loaded config:\n%s", b.String())

	// Setup the log output.
	if config.LogFile == "" {
		log.SetOutput(os.Stderr)
		closer = func() error { return nil }
	} else {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatalf("error opening log file: %v", err)
		}
		f.Write(logBuf.Bytes()) // Write log output prior to this point
		log.Printf("suppress stderr logging (redirected to %s)", f.Name())
		log.SetOutput(f)
		closer = f.Close
	}

	return config, closer
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "\t%s CONFIG_PATH\n", os.Args[0])
		os.Exit(1)
	}
	config, closer := loadConfig(os.Args[1])
	defer closer()

	// Setup signal handler to initiate shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		log.Printf("received %v - initiating shutdown", <-sigc)
		cancel()
	}()

	// Create a new tunnel device (requires root privileges).
	iface, err := water.NewTUN(config.TunnelDevice)
	if err != nil {
		log.Fatalf("error creating tun device: %v", err)
	}
	defer iface.Close()
	if err := exec.Command("/sbin/ip", "link", "set", "dev", config.TunnelDevice, "mtu", "1300").Run(); err != nil {
		log.Fatalf("ip link error: %v", err)
	}
	if err := exec.Command("/sbin/ip", "addr", "add", config.TunnelAddress+"/24", "dev", config.TunnelDevice).Run(); err != nil {
		log.Fatalf("ip addr error: %v", err)
	}
	if err := exec.Command("/sbin/ip", "link", "set", "dev", config.TunnelDevice, "up").Run(); err != nil {
		log.Fatalf("ip link error: %v", err)
	}

	// Create a new UDP socket.
	var cn *net.UDPConn
	serverMode := strings.HasPrefix(config.NetworkAddress, "0.0.0.0:")
	if serverMode {
		laddr, err := net.ResolveUDPAddr("udp", config.NetworkAddress)
		if err != nil {
			log.Fatalf("error resolving address: %v", err)
		}
		cn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			log.Fatalf("error listening on socket: %v", err)
		}
		log.Println("daemon started in server mode")
	} else {
		laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
		if err != nil {
			log.Fatalf("error resolving address: %v", err)
		}
		cn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			log.Fatalf("error listening on socket: %v", err)
		}
		log.Println("daemon started in client mode")
	}
	defer cn.Close()

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435

	// If in client mode, start a goroutine that polls for any changes in the
	// server address due to DNS updates.
	var atomicRaddr atomic.Value
	atomicRaddr.Store((*net.UDPAddr)(nil))
	if !serverMode {
		addr, err := net.ResolveUDPAddr("udp", config.NetworkAddress)
		if err != nil {
			log.Fatalf("error resolving address: %v", err)
		}
		atomicRaddr.Store(addr)
		go func() {
			for range time.Tick(30 * time.Second) {
				addr, err := net.ResolveUDPAddr("udp", config.NetworkAddress)
				if addr != nil && err == nil {
					atomicRaddr.Store(addr)
				}
			}
		}()
	}

	pf := newPortFilter(config.AllowedPorts)

	// Handle outbound traffic.
	go func() {
		b := make([]byte, 1<<16)
		for {
			n, err := iface.Read(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				log.Printf("tun read error: %v", err)
				continue
			}

			raddr := atomicRaddr.Load().(*net.UDPAddr)
			if pf.Filter(b[:n], outbound) || raddr == nil {
				logPacket(b[:n], outbound, true)
				continue
			}

			if _, err := cn.WriteToUDP(b[:n], raddr); err != nil {
				log.Printf("net write error: %v", err)
			}
			logPacket(b[:n], outbound, false)
		}
	}()

	// Handle inbound traffic.
	go func() {
		b := make([]byte, 1<<16)
		for {
			n, raddr, err := cn.ReadFromUDP(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				log.Printf("net read error: %v", err)
				continue
			}

			if pf.Filter(b[:n], inbound) {
				logPacket(b[:n], inbound, true)
				continue
			}

			if serverMode {
				// TODO(dsnet): There is no security here that verifies that
				// the new IP address is really the remote endpoint.
				// It is trivial for an attacker to send spoof packets that
				// redirect the UDP traffic to some other address.
				// The extent of the damage done is dropped connections.
				if !equalAddr(atomicRaddr.Load().(*net.UDPAddr), raddr) {
					atomicRaddr.Store(raddr)
					log.Printf("switching remote address: %v", raddr)
				}
			}

			if _, err := iface.Write(b[:n]); err != nil {
				log.Printf("tun write error: %v", err)
			}
			logPacket(b[:n], inbound, false)
		}
	}()

	<-ctx.Done()
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func equalAddr(x, y *net.UDPAddr) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return bytes.Equal(x.IP, y.IP) && x.Port == y.Port && x.Zone == y.Zone
}
