// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

const maxEvents = 2048

type Request struct {
	SchemaVersion      int      `json:"schemaVersion"`
	Command            string   `json:"command"`
	ExpectedGeneration *uint64  `json:"expectedGeneration,omitempty"`
	ExpectedInstanceID *string  `json:"expectedInstanceId,omitempty"`
	ProcessPaths       []string `json:"processPaths,omitempty"`
	AfterSequence      uint64   `json:"afterSequence,omitempty"`
	Limit              uint32   `json:"limit,omitempty"`
}

type Event struct {
	Sequence           uint64  `json:"sequence"`
	TimeMS             int64   `json:"timeMs"`
	FlowID             string  `json:"flowId"`
	PID                int     `json:"pid,omitempty"`
	UID                *uint32 `json:"uid,omitempty"`
	ProcessPath        string  `json:"processPath,omitempty"`
	ProcessStartTicks  string  `json:"processStartTicks,omitempty"`
	IdentityConfidence string  `json:"identityConfidence"`
	SourceIP           string  `json:"sourceIp"`
	SourcePort         uint16  `json:"sourcePort"`
	DestinationIP      string  `json:"destinationIp"`
	DestinationPort    uint16  `json:"destinationPort"`
	Network            string  `json:"network"`
	Direction          string  `json:"direction"`
	PacketBytes        uint32  `json:"packetBytes"`
	Verdict            string  `json:"verdict"`
	PolicyGeneration   uint64  `json:"policyGeneration"`
}

type Response struct {
	SchemaVersion          int      `json:"schemaVersion"`
	OK                     bool     `json:"ok"`
	Error                  string   `json:"error,omitempty"`
	Platform               string   `json:"platform"`
	AdapterID              string   `json:"adapterId"`
	InstanceID             string   `json:"instanceId"`
	Ready                  bool     `json:"ready"`
	Installed              bool     `json:"installed"`
	Active                 bool     `json:"active"`
	EnforcementActive      bool     `json:"enforcementActive"`
	Authenticated          bool     `json:"authenticated"`
	PolicyInitialized      bool     `json:"policyInitialized"`
	Monitoring             bool     `json:"monitoring"`
	Generation             uint64   `json:"generation"`
	ProcessPaths           []string `json:"processPaths"`
	Coverage               string   `json:"coverage"`
	UnknownIdentityAction  string   `json:"unknownIdentityAction"`
	ExistingFlowBehavior   string   `json:"existingFlowBehavior"`
	Reason                 string   `json:"reason"`
	ByteSemantics          string   `json:"byteSemantics"`
	HistoryDurable         bool     `json:"historyDurable"`
	Directions             []string `json:"directions"`
	EventSequence          uint64   `json:"eventSequence"`
	DroppedEvents          uint64   `json:"droppedEvents"`
	UnknownIdentityPackets uint64   `json:"unknownIdentityPackets"`
	DecodeErrors           uint64   `json:"decodeErrors"`
	QueueErrors            uint64   `json:"queueErrors"`
	ObservedUpload         uint64   `json:"observedUpload"`
	ObservedDownload       uint64   `json:"observedDownload"`
	Events                 []Event  `json:"events,omitempty"`
	NextSequence           uint64   `json:"nextSequence,omitempty"`
}

type adapterState struct {
	mu                sync.Mutex
	policy            BanPolicy
	policyInitialized bool
	policyPath        string
	instanceID        string
	queueHealthy      bool
	tableInstalled    bool
	tableChecked      time.Time
	reason            string
	eventSequence     uint64
	events            []Event
	droppedEvents     uint64
	unknownPackets    uint64
	decodeErrors      uint64
	queueErrors       uint64
	upload, download  uint64
}

func newState(policyPath string) (*adapterState, error) {
	policy, initialized, err := loadPolicy(policyPath)
	if err != nil {
		return nil, err
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, err
	}
	return &adapterState{policy: policy, policyInitialized: initialized, policyPath: policyPath, instanceID: hex.EncodeToString(epoch[:]), events: make([]Event, 0, maxEvents)}, nil
}

func (s *adapterState) readyLocked() bool {
	return s.queueHealthy && s.tableInstalled && !s.tableChecked.IsZero() && time.Since(s.tableChecked) <= 5*time.Second
}

func (s *adapterState) responseLocked() Response {
	ready := s.readyLocked()
	reason := s.reason
	if !ready && reason == "" {
		reason = "Native queues and the dedicated nftables table have not been verified"
	} else if !s.policyInitialized && reason == "" {
		reason = "No native ban policy initialized; queued traffic is blocked until explicit policy application"
	}
	active := ready
	existing := "unavailable"
	if active {
		existing = "drop"
	}
	return Response{
		SchemaVersion: 1, OK: true, Platform: "linux", AdapterID: "opensnitch-nfqueue", InstanceID: s.instanceID,
		Ready: ready, Installed: s.tableInstalled, Active: active, EnforcementActive: active, Authenticated: true,
		PolicyInitialized: s.policyInitialized, Monitoring: ready, Generation: s.policy.Generation,
		ProcessPaths: append([]string{}, s.policy.ProcessPaths...), Coverage: "host_namespace_tcp_udp",
		UnknownIdentityAction: "block", ExistingFlowBehavior: existing, Reason: reason,
		ByteSemantics: "observed_ip_packet_bytes", HistoryDurable: false, Directions: []string{"outbound", "inbound"},
		EventSequence: s.eventSequence, DroppedEvents: s.droppedEvents, UnknownIdentityPackets: s.unknownPackets,
		DecodeErrors: s.decodeErrors, QueueErrors: s.queueErrors, ObservedUpload: s.upload, ObservedDownload: s.download,
	}
}

func (s *adapterState) handle(request Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if request.SchemaVersion != 1 {
		err = errors.New("unsupported native request schema")
	} else {
		switch request.Command {
		case "status":
			if request.ExpectedGeneration != nil || request.ExpectedInstanceID != nil || request.ProcessPaths != nil || request.AfterSequence != 0 || request.Limit != 0 {
				err = errors.New("unexpected status request fields")
			}
		case "apply-bans":
			if request.AfterSequence != 0 || request.Limit != 0 || request.ExpectedGeneration == nil || request.ExpectedInstanceID == nil {
				err = errors.New("apply-bans requires expectedInstanceId, expectedGeneration and processPaths only")
			} else if *request.ExpectedInstanceID != s.instanceID {
				err = errors.New("native daemon instance changed; reload before applying")
			} else if !s.readyLocked() {
				err = errors.New("native queues and owned table are not ready; policy was not changed")
			} else if *request.ExpectedGeneration != s.policy.Generation {
				err = errors.New("native ban generation changed; reload before applying")
			} else if s.policy.Generation == math.MaxUint64 {
				err = errors.New("native ban generation exhausted")
			} else if err = validatePaths(request.ProcessPaths); err == nil {
				next := BanPolicy{SchemaVersion: 1, Generation: s.policy.Generation + 1, ProcessPaths: append([]string{}, request.ProcessPaths...)}
				err = savePolicy(s.policyPath, next)
				var published *publishedPolicyError
				if err == nil || errors.As(err, &published) {
					s.policy, s.policyInitialized = next, true
				}
			}
		case "events":
			if request.ExpectedGeneration != nil || request.ExpectedInstanceID != nil || request.ProcessPaths != nil || request.Limit > 256 || request.AfterSequence > s.eventSequence {
				err = errors.New("invalid events cursor or limit; reset cursor when instanceId changes")
			}
		default:
			err = errors.New("unsupported native command")
		}
	}
	response := s.responseLocked()
	if err != nil {
		response.OK, response.Error, response.Reason = false, err.Error(), err.Error()
		return response
	}
	if request.Command == "events" {
		limit := request.Limit
		if limit == 0 {
			limit = 256
		}
		response.NextSequence = request.AfterSequence
		for _, event := range s.events {
			if event.Sequence > request.AfterSequence {
				response.Events = append(response.Events, event)
				encoded, err := json.Marshal(response)
				if err != nil || len(encoded) > maxJSON-32 {
					response.Events = response.Events[:len(response.Events)-1]
					break
				}
				response.NextSequence = event.Sequence
				if len(response.Events) == int(limit) {
					break
				}
			}
		}
	}
	return response
}

func (s *adapterState) decideLocked(tuple Tuple, identity Identity, direction string) Event {
	verdict := "block"
	confidence := "unknown"
	var uid *uint32
	if identity.PID > 0 && identity.ProcessPath != "" {
		confidence = "inferred"
		uid = &identity.UID
		if s.readyLocked() && s.policyInitialized {
			verdict = "allow"
			for _, path := range s.policy.ProcessPaths {
				if identity.ProcessPath == path {
					verdict = "block"
					break
				}
			}
		}
	} else {
		s.unknownPackets++
	}
	local, remote, localPort, remotePort := tuple.Source, tuple.Destination, tuple.SourcePort, tuple.DestPort
	if direction == "inbound" {
		local, remote, localPort, remotePort = remote, local, remotePort, localPort
	}
	return Event{TimeMS: time.Now().UnixMilli(), FlowID: fmt.Sprintf("%s:%s:%d:%s:%d:%d:%s", tuple.Network, local, localPort, remote, remotePort, identity.PID, identity.StartTicks),
		PID: identity.PID, UID: uid, ProcessPath: identity.ProcessPath, ProcessStartTicks: identity.StartTicks,
		IdentityConfidence: confidence, SourceIP: tuple.Source.String(), SourcePort: tuple.SourcePort,
		DestinationIP: tuple.Destination.String(), DestinationPort: tuple.DestPort, Network: tuple.Network,
		Direction: direction, PacketBytes: tuple.PacketBytes, Verdict: verdict, PolicyGeneration: s.policy.Generation}
}

func (s *adapterState) recordLocked(event Event) {
	if s.eventSequence == math.MaxUint64 {
		s.queueHealthy = false
		s.reason = "Native event sequence exhausted"
		return
	}
	s.eventSequence++
	event.Sequence = s.eventSequence
	if event.Direction == "outbound" {
		s.upload += uint64(event.PacketBytes)
	} else {
		s.download += uint64(event.PacketBytes)
	}
	if len(s.events) == maxEvents {
		copy(s.events, s.events[1:])
		s.events = s.events[:maxEvents-1]
		s.droppedEvents++
	}
	s.events = append(s.events, event)
}
