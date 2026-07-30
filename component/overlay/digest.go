package overlay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
)

// Digests identify one generation's content. They are the only thing the
// coordinator, mihomo and the processor compare when they need to agree that
// they are talking about the same policy, so their construction has to be
// unambiguous rather than merely convenient.
type Digests struct {
	// Overall covers every field of the document.
	Overall string `json:"overall"`
	// Projection covers exactly the subset mihomo enforces. Two documents that
	// differ only in fields mihomo never reads share a projection digest, which
	// is what makes shadow comparison during migration meaningful.
	Projection string `json:"projection"`
	// Bundle and CertificateHostSet are carried through opaquely from the
	// document; mihomo never recomputes them.
	Bundle             string `json:"bundle,omitempty"`
	CertificateHostSet string `json:"certificateHostSet,omitempty"`
}

// canonical is a deterministic, injection-proof serializer. Every value is
// written as a type tag, a length and the bytes, so no combination of field
// values can produce the same byte stream as a different structure. A plain
// concatenation with separators cannot promise that: a rule whose value
// contains the separator would collide with a different rule list.
type canonical struct{ h hash.Hash }

func newCanonical() *canonical { return &canonical{h: sha256.New()} }

func (c *canonical) tag(t byte) { c.h.Write([]byte{t}) }

func (c *canonical) str(s string) {
	c.tag('s')
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	c.h.Write(n[:])
	c.h.Write([]byte(s))
}

func (c *canonical) uint(v uint64) {
	c.tag('u')
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	c.h.Write(n[:])
}

func (c *canonical) boolean(b bool) {
	c.tag('b')
	if b {
		c.h.Write([]byte{1})
	} else {
		c.h.Write([]byte{0})
	}
}

func (c *canonical) list(n int) {
	c.tag('l')
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	c.h.Write(b[:])
}

func (c *canonical) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

// writeProjection emits the subset of the document that mihomo enforces.
// Order is preserved everywhere it is semantically significant: the client rule
// list is first-match, so a reordering is a different policy and must produce a
// different digest.
func (c *canonical) writeProjection(d *Document) {
	c.str("mihomo-projection/v2")
	c.uint(uint64(d.SchemaVersion))
	c.str(d.Owner)
	c.str(d.GenerationID)
	c.str(d.ParentGenerationID)
	c.uint(d.DocumentRevision)
	c.str(string(d.TransitionMode))

	c.list(len(d.ProcessorTargets))
	for _, p := range d.ProcessorTargets {
		c.str(p.ID)
		c.str(p.Name)
	}

	c.list(len(d.Client.Rules))
	for _, r := range d.Client.Rules {
		c.str(string(r.Kind))
		c.str(r.Value)
		c.str(string(r.Network))
		c.list(len(r.Ports))
		for _, p := range r.Ports {
			c.uint(uint64(p.From))
			c.uint(uint64(p.To))
		}
		c.list(len(r.KeywordsAny))
		for _, kw := range r.KeywordsAny {
			c.str(kw)
		}
		c.list(len(r.KeywordsAll))
		for _, kw := range r.KeywordsAll {
			c.str(kw)
		}
		c.str(string(r.Action))
		c.str(r.Processor)
		c.str(r.Owner)
	}

	c.list(len(d.Egress.Capabilities))
	for _, cap := range d.Egress.Capabilities {
		c.str(cap.ID)
		c.str(cap.Listener)
		c.boolean(cap.PublicOnly)
		c.str(cap.ResolverProfile)
		c.list(len(cap.Bindings))
		for _, bind := range cap.Bindings {
			c.str(bind.Group)
			c.boolean(bind.AllowDirect)
			// Without this an unbounded binding and a bounded one with an empty
			// allowlist would hash the same, and a generation that widened the
			// policy could be accepted as unchanged.
			c.boolean(bind.Unbounded)
			c.list(len(bind.Destinations))
			for _, d := range bind.Destinations {
				c.str(string(d.Kind))
				c.str(d.Value)
				c.list(len(d.Ports))
				for _, p := range d.Ports {
					c.uint(uint64(p.From))
					c.uint(uint64(p.To))
				}
			}
		}
		c.str(cap.Owner)
	}

	c.list(len(d.ResolverProfiles))
	for _, p := range d.ResolverProfiles {
		c.str(p.Name)
		c.boolean(p.PreferGo)
		c.list(len(p.Nameservers))
		for _, ns := range p.Nameservers {
			c.str(ns)
		}
	}
}

// ComputeDigests derives the generation's identity from its content.
func ComputeDigests(d *Document) Digests {
	proj := newCanonical()
	proj.writeProjection(d)
	projection := proj.sum()

	all := newCanonical()
	all.str("overlay-document/v1")
	all.writeProjection(d)
	all.str(d.SidecarBundleDigest)
	all.str(d.CertificateHostSetDigest)
	overall := all.sum()

	return Digests{
		Overall:            overall,
		Projection:         projection,
		Bundle:             d.SidecarBundleDigest,
		CertificateHostSet: d.CertificateHostSetDigest,
	}
}

// ResolverProfileSetDigest identifies just the resolver profiles. The commit
// path compares this against the previous generation's value to decide whether
// the resolver answer cache must be invalidated in the same swap. Without that
// check a generation that changes the resolver profile keeps serving the
// previous profile's cached answers until their TTLs expire, which silently
// breaks the promise that one snapshot swap is the linearization point.
func ResolverProfileSetDigest(profiles []ResolverProfile) string {
	c := newCanonical()
	c.str("resolver-profile-set/v1")
	c.list(len(profiles))
	for _, p := range profiles {
		c.str(p.Name)
		c.boolean(p.PreferGo)
		c.list(len(p.Nameservers))
		for _, ns := range p.Nameservers {
			c.str(ns)
		}
	}
	return c.sum()
}

// CapabilitySetDigest identifies the egress capability table. It is exposed on
// readback so a coordinator can tell a capability-only change apart from a
// capture-rule change without diffing the whole document.
func CapabilitySetDigest(caps []EgressCapability) string {
	c := newCanonical()
	c.str("capability-set/v2")
	c.list(len(caps))
	for _, cap := range caps {
		c.str(cap.ID)
		c.str(cap.Listener)
		c.boolean(cap.PublicOnly)
		c.str(cap.ResolverProfile)
		c.list(len(cap.Bindings))
		for _, bind := range cap.Bindings {
			c.str(bind.Group)
			c.boolean(bind.AllowDirect)
			// Without this an unbounded binding and a bounded one with an empty
			// allowlist would hash the same, and a generation that widened the
			// policy could be accepted as unchanged.
			c.boolean(bind.Unbounded)
			c.list(len(bind.Destinations))
			for _, d := range bind.Destinations {
				c.str(string(d.Kind))
				c.str(d.Value)
				c.list(len(d.Ports))
				for _, p := range d.Ports {
					c.uint(uint64(p.From))
					c.uint(uint64(p.To))
				}
			}
		}
	}
	return c.sum()
}

// DependencyClosureDigest is the fingerprint of everything outside the overlay
// that the overlay's correctness depends on. It is what the core configuration
// revision is derived from, and it is deliberately broad: each entry listed
// here is a surface that can move traffic out of the anchored rule list, so
// leaving one out would let a config change silently invalidate an active
// generation.
type DependencyClosureDigest struct {
	Mode          string
	Sniffer       string
	Listeners     string
	Tunnels       string
	Hosts         string
	Rules         string
	Groups        string
	Resolver      string
	AnchorsClient int
	AnchorsEgress int
}

// Sum reduces the closure to a single revision-bearing digest.
func (d DependencyClosureDigest) Sum() string {
	c := newCanonical()
	c.str("dependency-closure/v1")
	c.str(d.Mode)
	c.str(d.Sniffer)
	c.str(d.Listeners)
	c.str(d.Tunnels)
	c.str(d.Hosts)
	c.str(d.Rules)
	c.str(d.Groups)
	c.str(d.Resolver)
	c.str(strconv.Itoa(d.AnchorsClient))
	c.str(strconv.Itoa(d.AnchorsEgress))
	return c.sum()
}

// HashStrings is a small helper for building the per-area digests that feed
// DependencyClosureDigest. The caller is responsible for supplying the strings
// in a deterministic order.
func HashStrings(domain string, values ...string) string {
	c := newCanonical()
	c.str(domain)
	c.list(len(values))
	for _, v := range values {
		c.str(v)
	}
	return c.sum()
}
