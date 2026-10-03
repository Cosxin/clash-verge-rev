// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

func TestPacketTuplesAndFragmentFailure(t *testing.T) {
	for _, version := range []byte{4, 6} {
		for _, protocol := range []byte{6, 17} {
			header, transport := 20, 20
			if version == 6 {
				header = 40
			}
			if protocol == 17 {
				transport = 8
			}
			data := make([]byte, header+transport)
			if version == 4 {
				data[0], data[9] = 0x45, protocol
				binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
				copy(data[12:16], []byte{192, 0, 2, 1})
				copy(data[16:20], []byte{198, 51, 100, 2})
			} else {
				data[0], data[6] = 0x60, protocol
				binary.BigEndian.PutUint16(data[4:6], uint16(transport))
				source, destination := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
				copy(data[8:24], source[:])
				copy(data[24:40], destination[:])
			}
			binary.BigEndian.PutUint16(data[header:header+2], 12345)
			binary.BigEndian.PutUint16(data[header+2:header+4], 443)
			if protocol == 6 {
				data[header+12] = 0x50
			} else {
				binary.BigEndian.PutUint16(data[header+4:header+6], uint16(transport))
			}
			tuple, err := decodePacket(data)
			if err != nil || tuple.SourcePort != 12345 || tuple.DestPort != 443 || tuple.PacketBytes != uint32(len(data)) || !tuple.Source.IsValid() || !tuple.Destination.IsValid() {
				t.Fatalf("native tuple mismatch for IPv%d protocol%d: %+v %v", version, protocol, tuple, err)
			}
			if version == 4 {
				data[6] = 0x20
			} else {
				data[6] = 44
			}
			if _, err := decodePacket(data); err == nil {
				t.Fatal("fragmented packets must not become attributed allows")
			}
		}
	}
}

func TestNativeBanCASReadinessBothDirectionsAndBoundedEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	state, err := newState(path)
	if err != nil {
		t.Fatal(err)
	}
	generation := uint64(0)
	instance := state.instanceID
	request := Request{SchemaVersion: 1, Command: "apply-bans", ExpectedGeneration: &generation, ExpectedInstanceID: &instance, ProcessPaths: []string{"/usr/bin/blocked"}}
	state.queueHealthy = true
	if state.handle(request).OK {
		t.Fatal("queue binding alone must not allow native application")
	}
	state.tableInstalled, state.tableChecked = true, time.Now()
	bootstrap := state.handle(Request{SchemaVersion: 1, Command: "status"})
	if !bootstrap.Active || !bootstrap.Ready || bootstrap.PolicyInitialized || bootstrap.Generation != 0 || bootstrap.ExistingFlowBehavior != "drop" {
		t.Fatalf("healthy fail-closed queues must expose explicit first-policy initialization: %+v", bootstrap)
	}
	if state.decideLocked(Tuple{}, Identity{PID: 12, ProcessPath: "/usr/bin/allowed"}, "outbound").Verdict != "block" {
		t.Fatal("bootstrap readiness must not authorize any application before policy initialization")
	}
	applied := state.handle(request)
	if !applied.OK || applied.Generation != 1 || !applied.Active || !applied.PolicyInitialized {
		t.Fatalf("native policy not acknowledged: %+v", applied)
	}
	if state.handle(request).OK {
		t.Fatal("stale native application must not overwrite acknowledged bans")
	}
	reloaded, initialized, err := loadPolicy(path)
	if err != nil || !initialized || reloaded.Generation != 1 || len(reloaded.ProcessPaths) != 1 {
		t.Fatalf("private native policy did not survive reload: %+v %v", reloaded, err)
	}
	tuple := Tuple{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.2"), SourcePort: 12345, DestPort: 443, Network: "tcp", PacketBytes: 40}
	for _, direction := range []string{"inbound", "outbound"} {
		blocked := state.decideLocked(tuple, Identity{PID: 12, ProcessPath: "/usr/bin/blocked", StartTicks: "99"}, direction)
		allowed := state.decideLocked(tuple, Identity{PID: 13, ProcessPath: "/usr/bin/allowed", StartTicks: "100"}, direction)
		unknown := state.decideLocked(tuple, Identity{}, direction)
		if blocked.Verdict != "block" || unknown.Verdict != "block" || allowed.Verdict != "allow" || blocked.IdentityConfidence != "inferred" {
			t.Fatal("native bidirectional ban/unknown decisions were broadened")
		}
	}
	for index := 0; index < maxEvents+2; index++ {
		state.recordLocked(state.decideLocked(tuple, Identity{}, "outbound"))
	}
	page := state.handle(Request{SchemaVersion: 1, Command: "events", Limit: 2})
	if len(page.Events) != 2 || page.Events[0].Sequence != 3 || page.NextSequence != 4 || page.DroppedEvents != 2 || page.HistoryDurable {
		t.Fatalf("native event ring or cursor mismatch: %+v", page)
	}
	for _, paths := range [][]string{{"/usr/bin/../curl"}, {"/usr/bin/curl\n"}, {"/usr/bin/curl", "/usr/bin/curl"}} {
		if validatePaths(paths) == nil {
			t.Fatal("invalid/ambiguous process path accepted")
		}
	}
	var duplicate Request
	if decodeJSON(strings.NewReader(`{"schemaVersion":1,"command":"status","command":"apply-bans"}`), &duplicate) == nil {
		t.Fatal("duplicate native command accepted")
	}
	for _, invalid := range []string{`{"SchemaVersion":1,"command":"status"}`, `{"schemaVersion":1,"command":null}`} {
		if decodeJSON(strings.NewReader(invalid), &duplicate) == nil {
			t.Fatal("native request accepted ambiguous field spelling or null")
		}
	}
	for _, invalid := range []string{`{"schemaVersion":1,"processPaths":[]}`, `{"schemaVersion":1,"generation":0,"processPaths":null}`} {
		var policy BanPolicy
		if decodeJSON(strings.NewReader(invalid), &policy) == nil {
			t.Fatal("incomplete native policy must not initialize permissive known-app behavior")
		}
	}
}

func TestNativeBanCASRejectsRestartedOrMissingInstanceWithoutPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.json")
	state, err := newState(path)
	if err != nil {
		t.Fatal(err)
	}
	state.queueHealthy, state.tableInstalled, state.tableChecked = true, true, time.Now()
	generation, instance := uint64(0), state.instanceID
	request := Request{SchemaVersion: 1, Command: "apply-bans", ExpectedGeneration: &generation, ExpectedInstanceID: &instance, ProcessPaths: []string{"/usr/bin/blocked"}}
	if response := state.handle(request); !response.OK {
		t.Fatalf("initial instance-CAS failed: %+v", response)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newState(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.queueHealthy, restarted.tableInstalled, restarted.tableChecked = true, true, time.Now()
	if restarted.instanceID == instance || restarted.policy.Generation != 1 {
		t.Fatal("restart fixture must retain generation and change instance")
	}
	generation = 1
	request.ProcessPaths = []string{}
	for _, expected := range []*string{&instance, nil} {
		request.ExpectedInstanceID = expected
		if response := restarted.handle(request); response.OK || response.Generation != 1 || len(response.ProcessPaths) != 1 {
			t.Fatalf("same-generation stale/missing instance changed policy: %+v", response)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("rejected instance changed persisted native bans: %v", err)
		}
	}
	for _, input := range []string{
		`{"schemaVersion":1,"command":"apply-bans","expectedGeneration":1,"processPaths":[]}`,
		`{"schemaVersion":1,"command":"apply-bans","expectedGeneration":1,"expectedInstanceId":null,"processPaths":[]}`,
		`{"schemaVersion":1,"command":"apply-bans","expectedGeneration":1,"expectedInstanceId":7,"processPaths":[]}`,
	} {
		var decoded Request
		if decodeJSON(strings.NewReader(input), &decoded) == nil {
			t.Fatal("native mutation accepted missing/non-string instance schema")
		}
	}
	instance = restarted.instanceID
	request.ExpectedInstanceID = &instance
	if response := restarted.handle(request); !response.OK || response.Generation != 2 || len(response.ProcessPaths) != 0 {
		t.Fatalf("fresh instance-CAS did not acknowledge replacement: %+v", response)
	}
}

func fixtureProcess(t *testing.T, root string, pid int, inode, executable string) {
	t.Helper()
	base := filepath.Join(root, strconv.Itoa(pid))
	for _, directory := range []string{filepath.Join(base, "fd"), filepath.Join(base, "ns")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(base, "fd", "5"):   "socket:[" + inode + "]",
		filepath.Join(base, "exe"):       executable,
		filepath.Join(base, "ns", "net"): "net:[123]",
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	stat := strconv.Itoa(pid) + " (fixture process) S " + strings.Repeat("0 ", 18) + "99 0\n"
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSnitchDerivedIPv6ProcIdentityAndSharedSocketRejection(t *testing.T) {
	ip, port, err := procAddress("00000000000000000000000001000000:01BB")
	if err != nil || ip.String() != "::1" || port != 443 {
		t.Fatalf("IPv6 proc word endianness/width lost: %s %d %v", ip, port, err)
	}
	root := t.TempDir()
	for _, directory := range []string{filepath.Join(root, "net"), filepath.Join(root, "self", "ns")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("net:[123]", filepath.Join(root, "self", "ns", "net")); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
		if protocol == "tcp" {
			data += "0: 010200C0:3039 026433C6:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 777 1\n"
		}
		if err := os.WriteFile(filepath.Join(root, "net", protocol), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fixtureProcess(t, root, 12, "777", "/usr/bin/fixture")
	tuple := Tuple{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.2"), SourcePort: 12345, DestPort: 443, Network: "tcp"}
	identity, err := resolveProcess(root, tuple, time.Now().Add(time.Second))
	if err != nil || identity.PID != 12 || identity.ProcessPath != "/usr/bin/fixture" || identity.StartTicks != "99" || identity.UID != 1000 {
		t.Fatalf("native socket owner mismatch: %+v %v", identity, err)
	}
	fixtureProcess(t, root, 13, "777", "/usr/bin/other")
	if identity, err := resolveProcess(root, tuple, time.Now().Add(time.Second)); err == nil || identity.PID != 0 {
		t.Fatal("ambiguous inherited/shared socket must not permit either application")
	}
}

const ownedTableFixture = `{"nftables":[
{"table":{"family":"inet","name":"networkcontrol","comment":"networkcontrol-v1"}},
{"chain":{"family":"inet","table":"networkcontrol","name":"output","type":"filter","hook":"output","prio":0,"policy":"accept"}},
{"chain":{"family":"inet","table":"networkcontrol","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}},
{"rule":{"family":"inet","table":"networkcontrol","chain":"output","expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":{"set":["tcp","udp"]}}},{"queue":{"num":9100}}]}},
{"rule":{"family":"inet","table":"networkcontrol","chain":"input","expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":{"set":["tcp","udp"]}}},{"queue":{"num":9101}}]}}
]}`

func TestReadinessRejectsQueueBypassMissingHookAndUnownedTable(t *testing.T) {
	if err := verifyTableJSON([]byte(ownedTableFixture)); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		strings.Replace(ownedTableFixture, `"num":9100`, `"num":9100,"flags":["bypass"]`, 1),
		strings.Replace(ownedTableFixture, `"hook":"input"`, `"hook":"forward"`, 1),
		strings.Replace(ownedTableFixture, `networkcontrol-v1`, `opensnitch`, 1),
	} {
		if verifyTableJSON([]byte(unsafe)) == nil {
			t.Fatal("native readiness accepted an unsafe/unowned table")
		}
	}
	var document any
	if json.Unmarshal([]byte(ownedTableFixture), &document) != nil {
		t.Fatal("invalid owned nftables JSON fixture")
	}
}

func TestQueueWireUsesDedicatedFailClosedQueuesAndLocalHooks(t *testing.T) {
	attributes := queueBindAttributes()
	if len(attributes) != 5 || attributes[0].Type != 1 || len(attributes[0].Data) != 4 || attributes[0].Data[0] != 1 || attributes[0].Data[2] != 0 || attributes[0].Data[3] != 0 {
		t.Fatal("queue binding must not unbind/bind protocol families")
	}
	if attributes[3].Type != 4 || attributes[4].Type != 5 || binary.BigEndian.Uint32(attributes[3].Data) != 9 || binary.BigEndian.Uint32(attributes[4].Data) != 8 {
		t.Fatal("NFQUEUE fail-open must stay explicitly disabled")
	}
	for _, queue := range []uint16{outputQueue, inputQueue} {
		header := make([]byte, 7)
		binary.BigEndian.PutUint32(header[:4], 42)
		header[6] = 3
		if queue == inputQueue {
			header[6] = 1
		}
		wire, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: 1, Data: header}, {Type: 10, Data: []byte{0x45}}})
		if err != nil {
			t.Fatal(err)
		}
		message := netlink.Message{Header: netlink.Header{Type: 0x300}, Data: append(nfHeader(queue), wire...)}
		id, payload, err := packetMessage(message, queue)
		if err != nil || id != 42 || len(payload) != 1 || payload[0] != 0x45 {
			t.Fatalf("native packet framing failed: %d %v %v", id, payload, err)
		}
		if _, _, err := packetMessage(message, queue+2); err == nil {
			t.Fatal("packet from unrelated queue accepted")
		}
		header[6] = 2
		wire, err = netlink.MarshalAttributes([]netlink.Attribute{{Type: 1, Data: header}})
		if err != nil {
			t.Fatal(err)
		}
		message.Data = append(nfHeader(queue), wire...)
		if _, _, err := packetMessage(message, queue); err == nil {
			t.Fatal("forwarded packet must not be mislabeled as local application traffic")
		}
	}
}
