// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

const outputQueue uint16 = 9100
const inputQueue uint16 = 9101

func verifyTableJSON(data []byte) error {
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if len(data) > maxJSON || json.Unmarshal(data, &document) != nil {
		return errors.New("cannot parse dedicated nftables table")
	}
	tables, chains, rules := 0, make(map[string]bool), make(map[string]bool)
	for _, item := range document.NFTables {
		if len(item) != 1 {
			return errors.New("unexpected nftables object")
		}
		for kind, raw := range item {
			switch kind {
			case "metainfo":
			case "table":
				var table struct{ Family, Name, Comment string }
				if json.Unmarshal(raw, &table) != nil || table.Family != "inet" || table.Name != "networkcontrol" || table.Comment != "networkcontrol-v1" {
					return errors.New("dedicated table ownership marker is missing")
				}
				tables++
			case "chain":
				var chain struct {
					Family, Table, Name, Type, Hook, Policy string
					Prio                                    *int
				}
				if json.Unmarshal(raw, &chain) != nil || chain.Family != "inet" || chain.Table != "networkcontrol" || chain.Type != "filter" || chain.Policy != "accept" || chain.Prio == nil || *chain.Prio != 0 || (chain.Name != "input" && chain.Name != "output") || chain.Hook != chain.Name || chains[chain.Name] {
					return errors.New("dedicated nftables chain does not match expected hook")
				}
				chains[chain.Name] = true
			case "rule":
				var rule struct {
					Family, Table, Chain string
					Expr                 []map[string]json.RawMessage
				}
				if json.Unmarshal(raw, &rule) != nil || rule.Family != "inet" || rule.Table != "networkcontrol" || (rule.Chain != "input" && rule.Chain != "output") || rules[rule.Chain] || len(rule.Expr) != 2 {
					return errors.New("unexpected dedicated nftables rule")
				}
				if len(rule.Expr[0]) != 1 || len(rule.Expr[1]) != 1 {
					return errors.New("unexpected dedicated nftables expressions")
				}
				var match struct {
					Op    string
					Left  struct{ Meta struct{ Key string } }
					Right struct{ Set []string }
				}
				if json.Unmarshal(rule.Expr[0]["match"], &match) != nil || match.Op != "==" || match.Left.Meta.Key != "l4proto" || len(match.Right.Set) != 2 || !((match.Right.Set[0] == "tcp" && match.Right.Set[1] == "udp") || (match.Right.Set[0] == "udp" && match.Right.Set[1] == "tcp")) {
					return errors.New("dedicated queue rule must cover TCP and UDP")
				}
				var queue struct {
					Num   uint16
					Flags []string
				}
				expected := outputQueue
				if rule.Chain == "input" {
					expected = inputQueue
				}
				if json.Unmarshal(rule.Expr[1]["queue"], &queue) != nil || queue.Num != expected || len(queue.Flags) != 0 {
					return errors.New("dedicated queue number is wrong or queue bypass is enabled")
				}
				rules[rule.Chain] = true
			default:
				return fmt.Errorf("unexpected object in dedicated nftables table: %s", kind)
			}
		}
	}
	if tables != 1 || len(chains) != 2 || len(rules) != 2 {
		return errors.New("dedicated bidirectional nftables queues are not installed")
	}
	return nil
}
