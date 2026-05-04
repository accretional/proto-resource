// Package dns provides a ResourceResolver that derives domain ownership from
// the DNS SOA record's RNAME field (RFC 1035 §8). The RNAME encodes the
// responsible-person email address; no local state is required. This is the
// "remote authority" path for proto-domain/Domain resources — the SQLite
// OwnerStore (explicit registration) takes priority when present.
package dns

import (
	"context"

	"github.com/accretional/proto-domain/dns"
	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
)

// DomainResourceType is the canonical resource type string for domains.
const DomainResourceType = "proto-domain/Domain"

// Resolver implements identifier.ResourceResolver for proto-domain/Domain
// resources by querying the SOA record and extracting the RNAME as an email.
type Resolver struct {
	r *dns.Resolver
}

// New returns a Resolver backed by the host's system DNS resolver.
func New() *Resolver { return &Resolver{r: dns.DefaultResolver} }

var _ identifier.ResourceResolver = (*Resolver)(nil)

// CanResolve reports whether the resource is a proto-domain/Domain type.
func (d *Resolver) CanResolve(res *pb.Resource) bool {
	return res.GetType() == DomainResourceType
}

// Resolve looks up the SOA record for the domain and returns the RNAME
// converted to an email address as the owner identity.
func (d *Resolver) Resolve(ctx context.Context, res *pb.Resource) ([]*pb.Identity, error) {
	soas, err := d.r.LookupSOA(ctx, res.GetName())
	if err != nil {
		return nil, err
	}
	owners := make([]*pb.Identity, 0, len(soas))
	for _, soa := range soas {
		email := dns.MBoxToEmail(soa.MBox)
		owners = append(owners, &pb.Identity{Id: email, Name: email})
	}
	return owners, nil
}
