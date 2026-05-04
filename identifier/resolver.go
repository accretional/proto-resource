package identifier

import (
	"context"

	"github.com/accretional/proto-resource/pb"
)

// ResourceResolver resolves ownership dynamically for a specific resource type.
// It is the extension point for DNS-backed, gRPC-backed, or other external
// ownership sources. The server tries registered resolvers in order after the
// OwnerStore returns no results.
type ResourceResolver interface {
	// CanResolve reports whether this resolver handles the given resource type.
	CanResolve(res *pb.Resource) bool
	// Resolve returns all owner identities for the resource.
	Resolve(ctx context.Context, res *pb.Resource) ([]*pb.Identity, error)
}

// WithResourceResolver registers a resolver used when the OwnerStore has no
// entry for a resource. Multiple resolvers may be registered; the first whose
// CanResolve returns true is used.
func WithResourceResolver(r ResourceResolver) Option {
	return func(s *identifierServer) {
		s.resolvers = append(s.resolvers, r)
	}
}
