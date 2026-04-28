package sqlite_test

import (
	"context"
	"io"
	"testing"

	"github.com/accretional/proto-resource/identifier"
	sqlitestore "github.com/accretional/proto-resource/identifier/sqlite"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// emailFlow is a fake AuthFlow that accepts any Identity and returns a
// Resource whose Name is the email set at construction time — simulating
// what the WorkOS token flow does after verifying a JWT.
type emailFlow struct {
	email string
}

func (f *emailFlow) Match(_ *pb.Identity) bool { return true }

func (f *emailFlow) Handle(_ *pb.Identity, stream grpc.BidiStreamingServer[pb.Identity, pb.Resource]) error {
	return stream.Send(&pb.Resource{
		Name: f.email,
		Type: "identity.authenticated",
		Owners: []*pb.Resource{
			{Name: f.email, Type: "identity.email"},
		},
	})
}

var _ identifier.AuthFlow = (*emailFlow)(nil)

// fakeAuthStream is a minimal grpc.BidiStreamingServer used to drive Authenticate.
type fakeAuthStream struct {
	sent []*pb.Resource
	recv []*pb.Identity
	pos  int
}

func (f *fakeAuthStream) Send(r *pb.Resource) error { f.sent = append(f.sent, r); return nil }
func (f *fakeAuthStream) Recv() (*pb.Identity, error) {
	if f.pos >= len(f.recv) {
		return nil, io.EOF
	}
	r := f.recv[f.pos]
	f.pos++
	return r, nil
}
func (f *fakeAuthStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeAuthStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeAuthStream) SetTrailer(metadata.MD)       {}
func (f *fakeAuthStream) Context() context.Context     { return context.Background() }
func (f *fakeAuthStream) SendMsg(any) error            { return nil }
func (f *fakeAuthStream) RecvMsg(any) error            { return nil }

var _ grpc.BidiStreamingServer[pb.Identity, pb.Resource] = (*fakeAuthStream)(nil)

// domainResource builds the Resource representation of a domain.
// Type uses the proto-domain package path as a stable namespace.
func domainResource(fqdn string) *pb.Resource {
	return &pb.Resource{Type: "proto-domain/Domain", Name: fqdn}
}

// openStore creates an in-memory SQLite store seeded with the given
// (fqdn, ownerEmail) pairs as domain resources.
func openStore(t *testing.T, pairs [][2]string) *sqlitestore.OwnerStore {
	t.Helper()
	store, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	for _, p := range pairs {
		fqdn, email := p[0], p[1]
		if err := store.Register(ctx, "proto-domain/Domain", fqdn, email); err != nil {
			t.Fatalf("Register %q → %q: %v", fqdn, email, err)
		}
	}
	return store
}

// containsEmail reports whether any Identity in owners has Id == email.
func containsEmail(owners []*pb.Identity, email string) bool {
	for _, o := range owners {
		if o.GetId() == email {
			return true
		}
	}
	return false
}

// --- OwnerStore unit tests ---

func TestOwnerStore_OwnersKnownDomain(t *testing.T) {
	store := openStore(t, [][2]string{{"example.com", "alice@example.com"}})

	owners, err := store.Owners(context.Background(), domainResource("example.com"))
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if len(owners) != 1 {
		t.Fatalf("got %d owners, want 1", len(owners))
	}
	if owners[0].GetId() != "alice@example.com" {
		t.Errorf("Id = %q, want alice@example.com", owners[0].GetId())
	}
}

func TestOwnerStore_OwnersMultipleOwners(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"example.com", "bob@example.com"},
	})

	owners, err := store.Owners(context.Background(), domainResource("example.com"))
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if len(owners) != 2 {
		t.Fatalf("got %d owners, want 2", len(owners))
	}
	if !containsEmail(owners, "alice@example.com") {
		t.Error("alice@example.com not in owners")
	}
	if !containsEmail(owners, "bob@example.com") {
		t.Error("bob@example.com not in owners")
	}
}

func TestOwnerStore_OwnersUnknownDomainReturnsEmpty(t *testing.T) {
	store := openStore(t, nil)

	owners, err := store.Owners(context.Background(), domainResource("unknown.com"))
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("got %d owners for unregistered domain, want 0", len(owners))
	}
}

func TestOwnerStore_RegisterIsIdempotent(t *testing.T) {
	store := openStore(t, [][2]string{{"example.com", "alice@example.com"}})
	ctx := context.Background()

	// Registering the same (resource, email) pair again is a no-op.
	if err := store.Register(ctx, "proto-domain/Domain", "example.com", "alice@example.com"); err != nil {
		t.Fatalf("duplicate Register: %v", err)
	}
	owners, err := store.Owners(ctx, domainResource("example.com"))
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if len(owners) != 1 {
		t.Errorf("got %d owners after duplicate Register, want 1", len(owners))
	}
}

// --- Identifier server integration tests ---

func newServer(email string, store *sqlitestore.OwnerStore) pb.IdentifierServer {
	return identifier.NewIdentifierServer(
		identifier.WithAuthHandler(&identifier.AuthDispatcher{
			Flows: []identifier.AuthFlow{&emailFlow{email: email}},
		}),
		identifier.WithOwnerStore(store),
	)
}

// TestDomainOwnership_AuthenticateThenIdentify is the primary end-to-end
// scenario: authenticate as a user, then look up the first owner of a domain.
// The unary Identify RPC returns one owner; a streaming variant would be
// needed to enumerate all owners for a proper any-of check.
func TestDomainOwnership_AuthenticateThenIdentify(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"other.com", "bob@example.com"},
	})
	srv := newServer("alice@example.com", store)
	ctx := context.Background()

	stream := &fakeAuthStream{recv: []*pb.Identity{{Name: "alice"}}}
	if err := srv.Authenticate(stream); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	authResource := stream.sent[0]
	authenticatedEmail := authResource.GetName()

	ownerIdentity, err := srv.Identify(ctx, domainResource("example.com"))
	if err != nil {
		t.Fatalf("Identify example.com: %v", err)
	}
	if ownerIdentity.GetId() != authenticatedEmail {
		t.Errorf("owner %q != authenticated user %q", ownerIdentity.GetId(), authenticatedEmail)
	}
}

// TestDomainOwnership_MultipleOwnersAnyOf verifies that the store holds all
// co-owners and that any-of membership can be checked at the store layer.
func TestDomainOwnership_MultipleOwnersAnyOf(t *testing.T) {
	store := openStore(t, [][2]string{
		{"shared.com", "alice@example.com"},
		{"shared.com", "bob@example.com"},
	})
	ctx := context.Background()

	owners, err := store.Owners(ctx, domainResource("shared.com"))
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		if !containsEmail(owners, email) {
			t.Errorf("%s not found in owners", email)
		}
	}
}

// TestDomainOwnership_CrossUserLookup shows that Identify returns whoever
// actually owns the resource, not the authenticated user.
func TestDomainOwnership_CrossUserLookup(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"other.com", "bob@example.com"},
	})
	srv := newServer("alice@example.com", store)

	ownerIdentity, err := srv.Identify(context.Background(), domainResource("other.com"))
	if err != nil {
		t.Fatalf("Identify other.com: %v", err)
	}
	if ownerIdentity.GetId() != "bob@example.com" {
		t.Errorf("Id = %q, want bob@example.com", ownerIdentity.GetId())
	}
}

// TestDomainOwnership_UnregisteredDomainReturnsNotFound verifies that
// Identify for a domain with no owners returns codes.NotFound.
func TestDomainOwnership_UnregisteredDomainReturnsNotFound(t *testing.T) {
	store := openStore(t, nil)
	srv := newServer("alice@example.com", store)

	_, err := srv.Identify(context.Background(), domainResource("unregistered.com"))
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

// TestDomainOwnership_IdentifyWithNoStoreReturnsUnimplemented confirms the
// server degrades gracefully when no OwnerStore is configured.
func TestDomainOwnership_IdentifyWithNoStoreReturnsUnimplemented(t *testing.T) {
	srv := identifier.NewIdentifierServer()

	_, err := srv.Identify(context.Background(), domainResource("example.com"))
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}

// --- Authority integration tests ---

// TestAuthority_RegisteredDomainIsLocal verifies that Authority returns
// local_authority for a domain that has at least one owner in the store.
func TestAuthority_RegisteredDomainIsLocal(t *testing.T) {
	store := openStore(t, [][2]string{{"example.com", "alice@example.com"}})
	srv := newServer("alice@example.com", store)

	resp, err := srv.Authority(context.Background(), &pb.Identity{Name: "example.com"})
	if err != nil {
		t.Fatalf("Authority(example.com): %v", err)
	}
	if resp.GetLocalAuthority() == nil {
		t.Error("expected LocalAuthority for registered domain")
	}
}

// TestAuthority_UnregisteredDomainReturnsNotFound verifies that Authority
// returns codes.NotFound for a name not in the store, cleanly deferring
// remote authority lookup to a future implementation.
func TestAuthority_UnregisteredDomainReturnsNotFound(t *testing.T) {
	store := openStore(t, nil)
	srv := newServer("alice@example.com", store)

	_, err := srv.Authority(context.Background(), &pb.Identity{Name: "unknown.com"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

// TestDomainOwnership_SubdomainIsDistinctResource verifies that a subdomain
// can have a different owner from its apex, supporting delegated ownership.
func TestDomainOwnership_SubdomainIsDistinctResource(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"api.example.com", "ops@example.com"},
	})
	srv := newServer("alice@example.com", store)
	ctx := context.Background()

	apex, err := srv.Identify(ctx, domainResource("example.com"))
	if err != nil {
		t.Fatalf("Identify apex: %v", err)
	}
	sub, err := srv.Identify(ctx, domainResource("api.example.com"))
	if err != nil {
		t.Fatalf("Identify subdomain: %v", err)
	}
	if apex.GetId() == sub.GetId() {
		t.Errorf("apex and subdomain share owner %q; expected independent ownership", apex.GetId())
	}
}
