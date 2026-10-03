//go:build linux

// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type nativeQueue struct {
	conn      *netlink.Conn
	id        uint16
	direction string
}

func openQueue(id uint16, direction string) (*nativeQueue, error) {
	connection, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	queue := &nativeQueue{conn: connection, id: id, direction: direction}
	attributes, err := netlink.MarshalAttributes(queueBindAttributes())
	if err == nil {
		_, err = connection.Execute(netlink.Message{
			Header: netlink.Header{Type: 0x302, Flags: netlink.Request | netlink.Acknowledge},
			Data:   append(nfHeader(id), attributes...),
		})
	}
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("cannot bind dedicated NFQUEUE %d: %w", id, err)
	}
	return queue, nil
}

func (q *nativeQueue) verdict(id uint32, allow bool) error {
	header := make([]byte, 8)
	if allow {
		binary.BigEndian.PutUint32(header, 1)
	}
	binary.BigEndian.PutUint32(header[4:], id)
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: 2, Data: header}})
	if err != nil {
		return err
	}
	if err := q.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = q.conn.Send(netlink.Message{Header: netlink.Header{Type: 0x301, Flags: netlink.Request}, Data: append(nfHeader(q.id), attributes...)})
	return err
}

func (q *nativeQueue) run(ctx context.Context, state *adapterState) error {
	for ctx.Err() == nil {
		if err := q.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		messages, err := q.conn.Receive()
		if err != nil {
			var operation *netlink.OpError
			if errors.As(err, &operation) && operation.Timeout() {
				continue
			}
			return err
		}
		for _, message := range messages {
			if message.Header.Type == netlink.Done {
				continue
			}
			id, payload, err := packetMessage(message, q.id)
			if err != nil {
				return err
			}
			tuple, err := decodePacket(payload)
			if err != nil {
				state.mu.Lock()
				state.decodeErrors++
				state.mu.Unlock()
				if err := q.verdict(id, false); err != nil {
					return err
				}
				continue
			}
			localTuple := tuple
			if q.direction == "inbound" {
				localTuple.Source, localTuple.Destination = tuple.Destination, tuple.Source
				localTuple.SourcePort, localTuple.DestPort = tuple.DestPort, tuple.SourcePort
			}
			identity, _ := resolveProcess("/proc", localTuple, time.Now().Add(100*time.Millisecond))
			state.mu.Lock()
			event := state.decideLocked(tuple, identity, q.direction)
			// The same lock covers policy acknowledgement and verdict submission, avoiding an old allow after apply-bans returns.
			err = q.verdict(id, event.Verdict == "allow")
			if err == nil {
				state.recordLocked(event)
			}
			state.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
