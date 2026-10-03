// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type Tuple struct {
	Source      netip.Addr
	Destination netip.Addr
	SourcePort  uint16
	DestPort    uint16
	Network     string
	PacketBytes uint32
}

func decodePacket(data []byte) (Tuple, error) {
	var tuple Tuple
	if len(data) < 20 {
		return tuple, errors.New("truncated IP packet")
	}
	var protocol byte
	var offset, length int
	switch data[0] >> 4 {
	case 4:
		offset = int(data[0]&15) * 4
		length = int(binary.BigEndian.Uint16(data[2:4]))
		if offset < 20 || offset > len(data) || length < offset || length > len(data) || binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 {
			return tuple, errors.New("truncated or fragmented IPv4 packet")
		}
		tuple.Source = netip.AddrFrom4([4]byte(data[12:16]))
		tuple.Destination = netip.AddrFrom4([4]byte(data[16:20]))
		protocol = data[9]
	case 6:
		if len(data) < 40 {
			return tuple, errors.New("truncated IPv6 packet")
		}
		length = int(binary.BigEndian.Uint16(data[4:6])) + 40
		if length > len(data) || length == 40 {
			return tuple, errors.New("truncated IPv6 packet or unsupported jumbogram")
		}
		tuple.Source = netip.AddrFrom16([16]byte(data[8:24]))
		tuple.Destination = netip.AddrFrom16([16]byte(data[24:40]))
		protocol, offset = data[6], 40
		for count := 0; protocol != 6 && protocol != 17; count++ {
			if count >= 8 || offset+2 > length {
				return tuple, errors.New("unsupported IPv6 extension chain")
			}
			next, extensionLength := data[offset], (int(data[offset+1])+1)*8
			switch protocol {
			case 0, 43, 60:
			case 51:
				extensionLength = (int(data[offset+1]) + 2) * 4
			default:
				return tuple, errors.New("fragmented or unsupported IPv6 transport")
			}
			offset += extensionLength
			if offset > length {
				return tuple, errors.New("truncated IPv6 extension")
			}
			protocol = next
		}
	default:
		return tuple, errors.New("unsupported IP version")
	}
	if protocol != 6 && protocol != 17 {
		return tuple, errors.New("unsupported IP transport")
	}
	minimum := 8
	tuple.Network = "udp"
	if protocol == 6 {
		minimum, tuple.Network = 20, "tcp"
	}
	if offset+minimum > length {
		return tuple, errors.New("truncated transport header")
	}
	if protocol == 6 && (int(data[offset+12]>>4)*4 < 20 || offset+int(data[offset+12]>>4)*4 > length) {
		return tuple, errors.New("invalid TCP header length")
	}
	if protocol == 17 && (binary.BigEndian.Uint16(data[offset+4:offset+6]) < 8 || offset+int(binary.BigEndian.Uint16(data[offset+4:offset+6])) > length) {
		return tuple, errors.New("invalid UDP length")
	}
	tuple.SourcePort = binary.BigEndian.Uint16(data[offset : offset+2])
	tuple.DestPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	tuple.PacketBytes = uint32(length)
	return tuple, nil
}
