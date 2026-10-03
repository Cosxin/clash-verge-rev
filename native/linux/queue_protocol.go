// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/binary"
	"errors"

	"github.com/mdlayher/netlink"
)

func nfHeader(queue uint16) []byte {
	return []byte{0, 0, byte(queue >> 8), byte(queue)}
}

func queueBindAttributes() []netlink.Attribute {
	length, flags, mask := make([]byte, 4), make([]byte, 4), make([]byte, 4)
	binary.BigEndian.PutUint32(length, 4096)
	binary.BigEndian.PutUint32(flags, 8)
	binary.BigEndian.PutUint32(mask, 9)
	// Queue-only bind avoids OpenSnitch's global PF_UNBIND/PF_BIND. Fail-open is explicitly cleared.
	return []netlink.Attribute{
		{Type: 1, Data: []byte{1, 0, 0, 0}},
		{Type: 2, Data: []byte{0, 0, 255, 255, 2}},
		{Type: 3, Data: length},
		{Type: 4, Data: mask},
		{Type: 5, Data: flags},
	}
}

func packetMessage(message netlink.Message, queue uint16) (uint32, []byte, error) {
	hook := byte(3)
	if queue == inputQueue {
		hook = 1
	} else if queue != outputQueue {
		return 0, nil, errors.New("unknown native queue")
	}
	if message.Header.Type != 0x300 || len(message.Data) < 4 || binary.BigEndian.Uint16(message.Data[2:4]) != queue {
		return 0, nil, errors.New("unexpected native queue message")
	}
	attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
	if err != nil {
		return 0, nil, err
	}
	var id uint32
	var payload []byte
	foundHeader, foundPayload := false, false
	for _, attribute := range attributes {
		switch attribute.Type & 0x3fff {
		case 1:
			if len(attribute.Data) < 7 || foundHeader || attribute.Data[6] != hook {
				return 0, nil, errors.New("invalid native packet header/hook")
			}
			id, foundHeader = binary.BigEndian.Uint32(attribute.Data[:4]), true
		case 10:
			if foundPayload {
				return 0, nil, errors.New("duplicate native packet payload")
			}
			payload, foundPayload = attribute.Data, true
		}
	}
	if !foundHeader {
		return 0, nil, errors.New("missing native packet identity")
	}
	return id, payload, nil
}
