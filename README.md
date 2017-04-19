# UDP virtual private tunnel daemon #

## Introduction ##

This repository contains a simple implementation of a point-to-point virtual
private network by opening a TUN device and transferring raw traffic over UDP.
This VPN was designed to create a tunnel between two hosts:
1. A client host operating behind an obtrusive NAT which drops TCP connections
frequently, but happens to pass UDP traffic reliably.
2. A server host that is internet-accessible.

TUN traffic is sent ad-verbatim between the two endpoints via unencrypted
UDP packets. Thus, this should only be used if a more secure protocol
(like SSH; see [github.com/dsnet/sshtunnel](https://github.com/dsnet/sshtunnel))
is running on top of this VPN. In order to prevent attackers from connecting to
other locally binded sockets on the endpoints, a simple port filter is built-in
to restrict IP traffic to only the specified ports. Users of udptunnel should
also setup iptable rules as a secondary measure to restrict malicious traffic.

This only supports Linux.

## Usage ##

Build the daemon:

```go get -u github.com/dsnet/udptunnel```

Create a server configuration file:

```javascript
{
	"TunnelAddress": "10.0.0.1",
	"NetworkAddress": ":8000",
	"AllowedPorts": [22],
}
```

The `NetworkAddress` with an empty host indicates that the daemon is operating
in server mode.

Create a client configuration file:

```javascript
{
	"TunnelAddress": "10.0.0.2",
	"NetworkAddress": "server.example.com:8000",
	"AllowedPorts": [22],
}
```

The host `server.example.com` is assumed to resolve to some address where the
client can reach the server.

Start the daemon on both the client and server (assuming `$GOPATH/bin` is in your `$PATH`):

```
root@server.example.com $ udptunnel /path/to/config.json
root@client.example.com $ udptunnel /path/to/config.json
```

Try accessing the other endpoint (example is for client to server):

```
user@client.example.com $ ping 10.0.0.1
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_req=1 ttl=64 time=56.7 ms
64 bytes from 10.0.0.1: icmp_req=2 ttl=64 time=58.7 ms
64 bytes from 10.0.0.1: icmp_req=3 ttl=64 time=50.1 ms
64 bytes from 10.0.0.1: icmp_req=4 ttl=64 time=51.6 ms


user@client.example.com $ nmap 10.0.0.1
Host is up (0.063s latency).
PORT   STATE SERVICE
22/tcp open  ssh


user@client.example.com $ ssh 10.0.0.1
Password: ...
```

The above example shows the client trying to communicate with the server,
which is addressable at `10.0.0.1`. The example commands can be done from the
server by dialing the client at `10.0.0.2`, instead.
