package identifier

import (
	"context"

	"github.com/accretional/proto-resource/pb"
)

// OwnerStore resolves the owner identity for a resource.
//
// The interface is the distribution seam: the default SQLite implementation
// stores ownership locally; a remote implementation delegates to another
// Identifier node via the Authority/Identify RPCs, enabling federated
// ownership checks across a distributed deployment.
type OwnerStore interface {
	Identify(ctx context.Context, res *pb.Resource) (*pb.Identity, error)
}

// WithOwnerStore configures the store used by the Identify RPC.
func WithOwnerStore(store OwnerStore) Option {
	return func(s *identifierServer) {
		s.ownerStore = store
	}
}
