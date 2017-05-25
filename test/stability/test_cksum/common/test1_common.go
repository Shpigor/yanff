// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"github.com/intel-go/yanff/packet"
)

type Packetdata struct {
	F1, F2 uint64
}

func CheckPacketChecksums(p *packet.Packet) bool {
	status := false

	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		l3status := true
		if p.IPv4.HdrChecksum != packet.CalculateIPv4Checksum(p) {
			println("IPv4 checksum mismatch")
			l3status = false
		}

		if p.IPv4.NextProtoID == packet.UDPNumber {
			csum := packet.CalculateIPv4UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv4 UDP datagram checksum mismatch", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = l3status
			}
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			csum := packet.CalculateIPv4TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv4 TCP checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = l3status
			}
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			csum := packet.CalculateIPv6UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv6 UDP datagram checksum mismatch:", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = true
			}
		} else if p.IPv6.Proto == packet.TCPNumber {
			csum := packet.CalculateIPv6TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv6 TCP datagram checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = true
			}
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
	}

	return status
}

func CalculateChecksum(p *packet.Packet) {
	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		p.IPv4.HdrChecksum = packet.CalculateIPv4Checksum(p)

		if p.IPv4.NextProtoID == packet.UDPNumber {
			p.UDP.DgramCksum = packet.CalculateIPv4UDPChecksum(p)
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			p.TCP.Cksum = packet.CalculateIPv4TCPChecksum(p)
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
			println("TEST FAILED")
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			p.UDP.DgramCksum = packet.CalculateIPv6UDPChecksum(p)
		} else if p.IPv6.Proto == packet.TCPNumber {
			p.TCP.Cksum = packet.CalculateIPv6TCPChecksum(p)
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
			println("TEST FAILED")
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
		println("TEST FAILED")
	}
}
