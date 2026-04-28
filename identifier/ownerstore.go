package identifier

import (
	"context"

	"github.com/accretional/proto-resource/pb"
)

// OwnerStore resolves ownership for a resource.
//
// The interface is the distribution seam: the default SQLite implementation
// stores ownership locally; a remote implementation delegates to another
// Identifier node via the Authority/Identify RPCs, enabling federated
// ownership checks across a distributed deployment.
//
// Owners returns all identities that own the given resource. The unary
// Identify RPC surfaces only the first element; a streaming Identify or a
// dedicated HasAccess RPC would be needed for a proper any-of check over
// multiple owners.
type OwnerStore interface {
	Owners(ctx context.Context, res *pb.Resource) ([]*pb.Identity, error)
}

// WithOwnerStore configures the store used by the Identify RPC.
func WithOwnerStore(store OwnerStore) Option {
	return func(s *identifierServer) {
		s.ownerStore = store
	}
}
