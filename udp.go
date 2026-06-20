package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// udpProbes holds protocol-specific payloads for ports that stay silent on
// an empty datagram. Without a probe, "open" UDP services are easy to
// mistake for "open|filtered" since many simply drop unrecognized input.
var udpProbes = map[int][]byte{
	53:  dnsProbe(),
	123: ntpProbe(),
	161: snmpProbe(),
}

func dnsProbe() []byte {
	// minimal standard query for the root domain, type A
	return []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // flags: standard query
		0x00, 0x01, // questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // answer/authority/additional: 0
		0x00,       // root domain (QNAME)
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN
	}
}

func ntpProbe() []byte {
	p := make([]byte, 48)
	p[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	return p
}

func snmpProbe() []byte {
	// SNMPv1 GetRequest for sysDescr.0, community "public"
	return []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}
}

// udpScanPorts probes UDP ports on a host. It uses a connected UDP socket
// so a subsequent ICMP port-unreachable surfaces as ECONNREFUSED on Read —
// no raw socket / root needed. Ports that respond are "open"; ports that
// time out with no ICMP error are ambiguous ("open|filtered", since a
// firewall drop looks identical to a service silently ignoring the probe);
// ports that get ECONNREFUSED are closed and dropped from the results.
func udpScanPorts(ip string, ports []int, concurrency int, timeout time.Duration) map[int]string {
	sem := make(chan struct{}, concurrency)
	results := make(map[int]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := net.DialTimeout("udp", addr, timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			payload := udpProbes[p]
			conn.Write(payload)

			conn.SetReadDeadline(time.Now().Add(timeout))
			buf := make([]byte, 512)
			n, err := conn.Read(buf)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && n > 0:
				results[p] = "open"
			case isConnRefused(err):
				// closed: ICMP port unreachable
			default:
				results[p] = "open|filtered"
			}
		}()
	}
	wg.Wait()
	return results
}

func isConnRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "refused")
}
