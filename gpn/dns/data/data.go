// Package data embeds the datasets the DNS engine arbitrates with.
//
// They used to be files the installer copied to /etc/5gpn and the daemon read at
// startup, which made them deployment state: a host could run a binary whose
// arbitration logic and whose CN prefix list came from different releases, and
// nothing checked. --seed-defaults existed to reconcile that, and reload-rules.sh
// existed to re-read it, and both exist only because the data lived outside the
// program that depends on it.
//
// Embedding removes the question. The list a build arbitrates with is the list
// that build shipped with, and updating it is a release rather than a file copy.
// 126 KB.
package data

import (
	_ "embed"
)

// ChinaIPList is the CN IPv4 prefix set used for deterministic arbitration.
//
//go:embed china_ip_list.txt
var ChinaIPList string

// BlockDNSBypass and BlockDNSBypassKeyword name hosts that must not be allowed
// to reach a resolver other than this one.
//
//go:embed block-dns-bypass.txt
var BlockDNSBypass string

//go:embed block-dns-bypass.keyword.txt
var BlockDNSBypassKeyword string

// ProxyDomains is the seed set of names steered to the gateway.
//
//go:embed proxy-domains.txt
var ProxyDomains string
