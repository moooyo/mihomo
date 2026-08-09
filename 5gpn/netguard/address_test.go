package netguard

import (
	"net/netip"
	"testing"
)

func TestIsPubliclyRoutableRefusesSpecialPurposeAddresses(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "IPv4 this network", address: "0.1.2.3"},
		{name: "IPv4 private 10", address: "10.1.2.3"},
		{name: "IPv4 shared", address: "100.64.0.1"},
		{name: "IPv4 loopback", address: "127.0.0.1"},
		{name: "IPv4 link local", address: "169.254.169.254"},
		{name: "IPv4 private 172", address: "172.16.0.1"},
		{name: "IPv4 IETF protocols", address: "192.0.0.9"},
		{name: "IPv4 documentation one", address: "192.0.2.1"},
		{name: "IPv4 6to4 relay", address: "192.88.99.1"},
		{name: "IPv4 private 192", address: "192.168.1.1"},
		{name: "IPv4 benchmark", address: "198.18.0.1"},
		{name: "IPv4 documentation two", address: "198.51.100.1"},
		{name: "IPv4 documentation three", address: "203.0.113.1"},
		{name: "IPv4 multicast", address: "233.252.0.1"},
		{name: "IPv4 reserved", address: "240.0.0.1"},
		{name: "IPv4 limited broadcast", address: "255.255.255.255"},
		{name: "IPv6 unspecified", address: "::"},
		{name: "IPv6 loopback", address: "::1"},
		{name: "IPv4 mapped public", address: "::ffff:8.8.8.8"},
		{name: "IPv6 NAT64 well known", address: "64:ff9b::808:808"},
		{name: "IPv6 NAT64 local", address: "64:ff9b:1::1"},
		{name: "IPv6 discard only", address: "100::1"},
		{name: "IPv6 IETF protocols", address: "2001::1"},
		{name: "IPv6 benchmarking", address: "2001:2::1"},
		{name: "IPv6 ORCHID", address: "2001:20::1"},
		{name: "IPv6 documentation", address: "2001:db8::1"},
		{name: "IPv6 6to4", address: "2002:c000:201::1"},
		{name: "IPv6 documentation two", address: "3fff::1"},
		{name: "IPv6 unallocated", address: "4000::1"},
		{name: "IPv6 SRv6 SID", address: "5f00::1"},
		{name: "IPv6 unique local", address: "fd00::1"},
		{name: "IPv6 link local", address: "fe80::1"},
		{name: "IPv6 site local", address: "fec0::1"},
		{name: "IPv6 multicast", address: "ff02::1"},
		{name: "IPv6 zoned global", address: "2001:4860:4860::8888%eth0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if IsPubliclyRoutable(netip.MustParseAddr(test.address)) {
				t.Fatalf("IsPubliclyRoutable(%s) = true", test.address)
			}
		})
	}
	if IsPubliclyRoutable(netip.Addr{}) {
		t.Fatal("invalid address was accepted")
	}
}

func TestIsPubliclyRoutableAcceptsOrdinaryGlobalUnicast(t *testing.T) {
	for _, address := range []string{
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"192.0.1.1",
		"198.20.0.1",
		"2001:200::1",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"2a00:1450:4001:81b::200e",
	} {
		if !IsPubliclyRoutable(netip.MustParseAddr(address)) {
			t.Fatalf("IsPubliclyRoutable(%s) = false", address)
		}
	}
}
