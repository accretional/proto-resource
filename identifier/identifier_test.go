package identifier_test

import (
	"context"
	"testing"

	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeOwnerStore is a minimal in-memory OwnerStore for unit tests.
type fakeOwnerStore struct {
	local  map[string]bool
	owners map[string][]*pb.Identity // key: "type/name"
}

func (f *fakeOwnerStore) IsLocal(_ context.Context, name string) (bool, error) {
	return f.local[name], nil
}

func (f *fakeOwnerStore) Owners(_ context.Context, res *pb.Resource) ([]*pb.Identity, error) {
	return f.owners[res.GetType()+"/"+res.GetName()], nil
}

var _ identifier.OwnerStore = (*fakeOwnerStore)(nil)

// --- Authority ---

func TestAuthority_EmptyRequestReturnsLocalAuthority(t *testing.T) {
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
	)
	resp, err := srv.Authority(context.Background(), &pb.Identity{})
	if err != nil {
		t.Fatalf("Authority() error: %v", err)
	}
	if resp.GetName() != "example.com" {
		t.Errorf("Name = %q, want example.com", resp.GetName())
	}
	if la := resp.GetLocalAuthority(); la == nil || la.GetName() != "alice" {
		t.Errorf("LocalAuthority.Name = %q, want alice", resp.GetLocalAuthority().GetName())
	}
}

func TestAuthority_OwnAuthorityNameAlwaysLocal(t *testing.T) {
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
	)
	resp, err := srv.Authority(context.Background(), &pb.Identity{Name: "example.com"})
	if err != nil {
		t.Fatalf("Authority(example.com) error: %v", err)
	}
	if resp.GetLocalAuthority() == nil {
		t.Error("expected LocalAuthority for server's own authority name")
	}
}

func TestAuthority_LocalNameReturnsLocalAuthority(t *testing.T) {
	store := &fakeOwnerStore{local: map[string]bool{"myapp.com": true}}
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
		identifier.WithOwnerStore(store),
	)
	resp, err := srv.Authority(context.Background(), &pb.Identity{Name: "myapp.com"})
	if err != nil {
		t.Fatalf("Authority(myapp.com) error: %v", err)
	}
	if resp.GetLocalAuthority() == nil {
		t.Error("expected LocalAuthority for locally registered name")
	}
}

func TestAuthority_UnknownNameReturnsNotFound(t *testing.T) {
	store := &fakeOwnerStore{local: map[string]bool{}}
	srv := identifier.NewIdentifierServer(
		identifier.WithOwnerStore(store),
	)
	_, err := srv.Authority(context.Background(), &pb.Identity{Name: "unknown.com"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestAuthority_NoStoreClaimsLocalForAnyName(t *testing.T) {
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
	)
	resp, err := srv.Authority(context.Background(), &pb.Identity{Name: "anything.com"})
	if err != nil {
		t.Fatalf("Authority(anything.com) without store: %v", err)
	}
	if resp.GetLocalAuthority() == nil {
		t.Error("expected LocalAuthority in single-server mode (no store)")
	}
}

// --- Authenticate ---

func TestAuthenticate_NilHandlerReturnsUnimplemented(t *testing.T) {
	srv := identifier.NewIdentifierServer()
	err := srv.Authenticate(&fakeStream{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

// --- Identify ---

func TestIdentify_NoStoreReturnsUnimplemented(t *testing.T) {
	srv := identifier.NewIdentifierServer()
	_, err := srv.Identify(context.Background(), &pb.Resource{Name: "example.com"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

func TestIdentify_SystemReturnsServiceIdentity(t *testing.T) {
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
	)
	resp, err := srv.Identify(context.Background(), &pb.Resource{Name: "system"})
	if err != nil {
		t.Fatalf("Identify(system) error: %v", err)
	}
	if resp.GetName() != "example.com" {
		t.Errorf("Name = %q, want example.com", resp.GetName())
	}
	if resp.GetLocalAuthority() == nil {
		t.Error("expected LocalAuthority in system identity")
	}
}

func TestIdentify_KnownResourceReturnsOwner(t *testing.T) {
	store := &fakeOwnerStore{
		owners: map[string][]*pb.Identity{
			"domain/example.com": {{Id: "alice@example.com", Name: "alice@example.com"}},
		},
	}
	srv := identifier.NewIdentifierServer(identifier.WithOwnerStore(store))
	resp, err := srv.Identify(context.Background(), &pb.Resource{Type: "domain", Name: "example.com"})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if resp.GetId() != "alice@example.com" {
		t.Errorf("Id = %q, want alice@example.com", resp.GetId())
	}
}

func TestIdentify_UnknownResourceReturnsNotFound(t *testing.T) {
	store := &fakeOwnerStore{owners: map[string][]*pb.Identity{}}
	srv := identifier.NewIdentifierServer(identifier.WithOwnerStore(store))
	_, err := srv.Identify(context.Background(), &pb.Resource{Type: "domain", Name: "unknown.com"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}
