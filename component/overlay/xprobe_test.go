package overlay_test

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/overlay"
	C "github.com/metacubex/mihomo/constant"
)

// mirror of 5gpn interceptRoutingRule
type rr struct {
	Action, Domain, DomainSuffix, IPCIDR, Network string
	DomainKeywords, AllDomainKeywords             []string
	DestinationPort                               int
}

// verbatim port of renderInterceptPolicyRule
func render(rule rr) string {
	matchers := make([]string, 0, 4)
	if rule.Domain != "" {
		matchers = append(matchers, "(DOMAIN,"+rule.Domain+")")
	}
	if rule.DomainSuffix != "" {
		matchers = append(matchers, "(DOMAIN-SUFFIX,"+rule.DomainSuffix+")")
	}
	if rule.IPCIDR != "" {
		kind := "IP-CIDR"
		if strings.Contains(rule.IPCIDR, ":") {
			kind = "IP-CIDR6"
		}
		matchers = append(matchers, "("+kind+","+rule.IPCIDR+",no-resolve)")
	}
	if len(rule.DomainKeywords) == 1 {
		matchers = append(matchers, "(DOMAIN-KEYWORD,"+rule.DomainKeywords[0]+")")
	} else if len(rule.DomainKeywords) > 1 {
		keywords := make([]string, 0, len(rule.DomainKeywords))
		for _, keyword := range rule.DomainKeywords {
			keywords = append(keywords, "(DOMAIN-KEYWORD,"+keyword+")")
		}
		matchers = append(matchers, "(OR,("+strings.Join(keywords, ",")+"))")
	}
	for _, keyword := range rule.AllDomainKeywords {
		matchers = append(matchers, "(DOMAIN-KEYWORD,"+keyword+")")
	}
	if rule.Network != "" {
		matchers = append(matchers, "(NETWORK,"+strings.ToUpper(rule.Network)+")")
	}
	if rule.DestinationPort != 0 {
		matchers = append(matchers, "(DST-PORT,"+strconv.Itoa(rule.DestinationPort)+")")
	}
	target := strings.ToUpper(rule.Action)
	if len(matchers) == 1 {
		matcher := strings.TrimSuffix(strings.TrimPrefix(matchers[0], "("), ")")
		parts := strings.Split(matcher, ",")
		if len(parts) >= 2 {
			if parts[0] == "OR" {
				return matcher + "," + target
			}
			if strings.HasPrefix(parts[0], "IP-CIDR") {
				return parts[0] + "," + parts[1] + "," + target + ",no-resolve"
			}
			return matcher + "," + target
		}
	}
	return "AND,(" + strings.Join(matchers, ",") + ")," + target
}

// verbatim port of overlayPolicyRule
func typedOf(rule rr) (overlay.ClientRule, bool) {
	out := overlay.ClientRule{Action: overlay.ActionReject}
	if strings.EqualFold(rule.Action, "direct") {
		out.Action = overlay.ActionDirect
	}
	primaries := 0
	if rule.Domain != "" {
		out.Kind, out.Value = overlay.SelectorDomain, rule.Domain
		primaries++
	}
	if rule.DomainSuffix != "" {
		out.Kind, out.Value = overlay.SelectorDomainSuffix, rule.DomainSuffix
		primaries++
	}
	if rule.IPCIDR != "" {
		out.Kind, out.Value = overlay.SelectorIPCIDR, rule.IPCIDR
		primaries++
	}
	if primaries > 1 {
		return overlay.ClientRule{}, false
	}
	out.KeywordsAny = append([]string(nil), rule.DomainKeywords...)
	out.KeywordsAll = append([]string(nil), rule.AllDomainKeywords...)
	if primaries == 0 {
		if len(out.KeywordsAny) == 0 && len(out.KeywordsAll) == 0 {
			return overlay.ClientRule{}, false
		}
		if len(out.KeywordsAny) == 1 && len(out.KeywordsAll) == 0 {
			out.Kind, out.Value = overlay.SelectorDomainKeyword, out.KeywordsAny[0]
			out.KeywordsAny = nil
		} else {
			out.Kind, out.Value = overlay.SelectorAny, ""
		}
	}
	if rule.Network != "" {
		out.Network = overlay.Network(strings.ToLower(rule.Network))
	}
	if rule.DestinationPort != 0 {
		p := uint16(rule.DestinationPort)
		out.Ports = []overlay.PortRange{{From: p, To: p}}
	}
	return out, true
}

var domains = []string{"", "capcutapi.com"}
var suffixes = []string{"", "capcutapi.com", "chat.bilibili.com"}
var cidrs = []string{"", "203.0.113.0/24"}
var anyKw = [][]string{nil, {"alisg", "tnc"}, {"p2p", "stun", "tracker"}}
var allKw = [][]string{nil, {"tnc"}, {"alisg", "tnc"}}
var nets = []string{"", "tcp", "udp"}
var ports = []int{0, 443}
var acts = []string{"reject", "direct"}

var hosts = []string{
	"", "capcutapi.com", "tnc.capcutapi.com", "tnc16-normal-alisg.capcutapi.com",
	"api.capcutapi.com", "notcapcutapi.com", "tnc.example.test",
	"chat.bilibili.com", "p2p.chat.bilibili.com", "stun.chat.bilibili.com",
	"tracker.chat.bilibili.com", "chat.bilibili.com.evil.test", "alisg.test",
	"stun.tnc.alisg.capcutapi.com", "TNC16-Normal-ALISG.CapCutAPI.com", "P2P.Chat.Bilibili.com", "Api.CapCutAPI.com",
}
var ips = []string{"", "203.0.113.7", "198.51.100.4"}

// 5gpn validateInterceptRoutingRule
func valid(r rr) bool {
	p := 0
	if r.Domain != "" {
		p++
	}
	if r.DomainSuffix != "" {
		p++
	}
	if r.IPCIDR != "" {
		p++
	}
	if p > 1 || (p == 0 && len(r.DomainKeywords) == 0 && len(r.AllDomainKeywords) == 0) {
		return false
	}
	if r.IPCIDR != "" && (len(r.DomainKeywords) > 0 || len(r.AllDomainKeywords) > 0) {
		return false
	}
	if len(r.DomainKeywords) == 1 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range r.DomainKeywords {
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	for _, k := range r.AllDomainKeywords {
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

func TestXProbeAllShapes(t *testing.T) {
	diverged := map[string]int{}
	examples := map[string]string{}
	total := 0
	for _, d := range domains {
		for _, s := range suffixes {
			for _, c := range cidrs {
				for _, ak := range anyKw {
					for _, lk := range allKw {
						for _, n := range nets {
							for _, pt := range ports {
								for _, a := range acts {
									r := rr{Action: a, Domain: d, DomainSuffix: s, IPCIDR: c, Network: n,
										DomainKeywords: ak, AllDomainKeywords: lk, DestinationPort: pt}
									if !valid(r) {
										continue
									}
									total++
									line := render(r)
									legacy := mustParseLegacy(t, line)
									tr, ok := typedOf(r)
									if !ok {
										diverged["typed-dropped"]++
										examples["typed-dropped"] = line
										continue
									}
									typed := compileTyped(t, tr)
									for _, h := range hosts {
										for _, ipStr := range ips {
											for _, port := range []uint16{80, 443} {
												for _, nw := range []C.NetWork{C.TCP, C.UDP} {
													md := &C.Metadata{NetWork: nw, Host: h, DstPort: port}
													var addr netip.Addr
													if ipStr != "" {
														addr = netip.MustParseAddr(ipStr)
														md.DstIP = addr
													}
													lm, _ := legacy.Match(md, C.RuleMatchHelper{})
													onw := overlay.NetworkTCP
													if nw == C.UDP {
														onw = overlay.NetworkUDP
													}
													td := typed.Client.Match(&overlay.MatchInput{
														Host: strings.ToLower(md.RuleHost()), DstIP: addr, DstPort: port, Network: onw})
													if lm != td.Matched {
														key := line
														diverged[key]++
														if examples[key] == "" {
															examples[key] = "host=" + h + " ip=" + ipStr + " port=" + strconv.Itoa(int(port)) + " net=" + nw.String() +
																" legacy=" + strconv.FormatBool(lm) + " typed=" + strconv.FormatBool(td.Matched)
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("shapes tested: %d", total)
	for k, v := range diverged {
		t.Errorf("DIVERGE %d cases  rule=%s  first=%s", v, k, examples[k])
	}
}
