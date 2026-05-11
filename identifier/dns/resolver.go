// Package dns provides a ResourceResolver that derives domain ownership from
// URI DNS records (RFC 7553). URI records at the zone apex encode contact
// information as "mailto:" and "tel:" URIs; no local state is required. This
// is the "remote authority" path for proto-domain/Domain resources — the
// SQLite OwnerStore (explicit registration) takes priority when present.
package dns

import (
	"context"
	"strings"

	"github.com/accretional/proto-domain/dns"
	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
)

// DomainResourceType is the canonical resource type string for domains.
const DomainResourceType = "proto-domain/Domain"

// Resolver implements identifier.ResourceResolver for proto-domain/Domain
// resources by querying URI records and extracting mailto: targets as identities.
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

// Resolve looks up URI records for the domain and returns any mailto: targets
// as owner identities. Records with tel: or other schemes are skipped — they
// carry contact info but not a stable identifier suitable for auth.
func (d *Resolver) Resolve(ctx context.Context, res *pb.Resource) ([]*pb.Identity, error) {
	uris, err := d.r.LookupURI(ctx, res.GetName())
	if err != nil {
		return nil, err
	}
	owners := make([]*pb.Identity, 0, len(uris))
	for _, u := range uris {
		if !strings.HasPrefix(u.Target, "mailto:") {
			continue
		}
		email := strings.TrimPrefix(u.Target, "mailto:")
		owners = append(owners, &pb.Identity{Id: email, Name: email})
	}
	return owners, nil
}
