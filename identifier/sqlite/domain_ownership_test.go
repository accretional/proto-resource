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

// fakeStream is a minimal grpc.BidiStreamingServer for unit tests.
type fakeStream struct {
	sent []*pb.Resource
	recv []*pb.Identity
	pos  int
}

func (f *fakeStream) Send(r *pb.Resource) error { f.sent = append(f.sent, r); return nil }
func (f *fakeStream) Recv() (*pb.Identity, error) {
	if f.pos >= len(f.recv) {
		return nil, io.EOF
	}
	r := f.recv[f.pos]
	f.pos++
	return r, nil
}
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) Context() context.Context     { return context.Background() }
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

var _ grpc.BidiStreamingServer[pb.Identity, pb.Resource] = (*fakeStream)(nil)

// domainResource builds the Resource representation of a domain.
// Type uses the proto-domain package path as a stable namespace.
// Name is the fully-qualified domain string (e.g. "example.com").
func domainResource(fqdn string) *pb.Resource {
	return &pb.Resource{Type: "proto-domain/Domain", Name: fqdn}
}

// openStore creates an in-memory SQLite store with the given ownership pairs
// seeded as domain resources.
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

// --- OwnerStore unit tests ---

func TestOwnerStore_IdentifyKnownDomain(t *testing.T) {
	store := openStore(t, [][2]string{{"example.com", "alice@example.com"}})

	got, err := store.Identify(context.Background(), domainResource("example.com"))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.GetId() != "alice@example.com" {
		t.Errorf("Id = %q, want %q", got.GetId(), "alice@example.com")
	}
	if got.GetName() != "alice@example.com" {
		t.Errorf("Name = %q, want %q", got.GetName(), "alice@example.com")
	}
}

func TestOwnerStore_IdentifyUnknownDomainReturnsNotFound(t *testing.T) {
	store := openStore(t, nil)

	_, err := store.Identify(context.Background(), domainResource("unknown.com"))
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestOwnerStore_RegisterReplacesOwner(t *testing.T) {
	store := openStore(t, [][2]string{{"example.com", "alice@example.com"}})
	ctx := context.Background()

	if err := store.Register(ctx, "proto-domain/Domain", "example.com", "bob@example.com"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := store.Identify(ctx, domainResource("example.com"))
	if err != nil {
		t.Fatalf("Identify after re-register: %v", err)
	}
	if got.GetId() != "bob@example.com" {
		t.Errorf("Id = %q after replace, want %q", got.GetId(), "bob@example.com")
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

// TestDomainOwnership_AuthenticateThenIdentify is the primary end-to-end scenario:
// authenticate as a user, then look up who owns a domain — demonstrating the
// full auth + ownership check the proto design is meant to support.
func TestDomainOwnership_AuthenticateThenIdentify(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"other.com", "bob@example.com"},
	})
	srv := newServer("alice@example.com", store)
	ctx := context.Background()

	stream := &fakeStream{recv: []*pb.Identity{{Name: "alice"}}}
	if err := srv.Authenticate(stream); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("Authenticate sent %d resources, want 1", len(stream.sent))
	}
	authResource := stream.sent[0]
	if authResource.GetType() != "identity.authenticated" {
		t.Errorf("auth resource Type = %q, want identity.authenticated", authResource.GetType())
	}
	authenticatedEmail := authResource.GetName()

	ownerIdentity, err := srv.Identify(ctx, domainResource("example.com"))
	if err != nil {
		t.Fatalf("Identify example.com: %v", err)
	}
	if ownerIdentity.GetId() != authenticatedEmail {
		t.Errorf("ownership mismatch: domain owner %q != authenticated user %q",
			ownerIdentity.GetId(), authenticatedEmail)
	}
}

// TestDomainOwnership_CrossUserLookup shows that Identify is not tied to the
// authenticated session — it returns whoever actually owns the resource.
func TestDomainOwnership_CrossUserLookup(t *testing.T) {
	store := openStore(t, [][2]string{
		{"example.com", "alice@example.com"},
		{"other.com", "bob@example.com"},
	})
	srv := newServer("alice@example.com", store)
	ctx := context.Background()

	ownerIdentity, err := srv.Identify(ctx, domainResource("other.com"))
	if err != nil {
		t.Fatalf("Identify other.com: %v", err)
	}
	if ownerIdentity.GetId() != "bob@example.com" {
		t.Errorf("Id = %q, want bob@example.com", ownerIdentity.GetId())
	}
}

// TestDomainOwnership_UnregisteredDomainReturnsNotFound verifies that Identify
// for a domain with no registered owner returns codes.NotFound.
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

// TestDomainOwnership_SubdomainIsDistinctResource verifies that a subdomain
// ("api.example.com") can have a different owner from its apex ("example.com").
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
		t.Errorf("apex and subdomain have the same owner %q; expected independent ownership", apex.GetId())
	}
}
