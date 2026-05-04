package dns_test

import (
	"context"
	"testing"
	"time"

	"github.com/accretional/proto-resource/identifier"
	dnsresolver "github.com/accretional/proto-resource/identifier/dns"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCanResolve(t *testing.T) {
	r := dnsresolver.New()
	cases := []struct {
		typ  string
		want bool
	}{
		{dnsresolver.DomainResourceType, true},
		{"other/Type", false},
		{"", false},
	}
	for _, c := range cases {
		got := r.CanResolve(&pb.Resource{Type: c.typ})
		if got != c.want {
			t.Errorf("CanResolve(%q) = %v, want %v", c.typ, got, c.want)
		}
	}
}

// TestResolve_Accretional verifies SOA RNAME → owner email via live DNS.
// Skipped with -short.
func TestResolve_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := dnsresolver.New()
	res := &pb.Resource{Type: dnsresolver.DomainResourceType, Name: "accretional.com"}
	owners, err := r.Resolve(ctx, res)
	if err != nil {
		t.Fatalf("Resolve(accretional.com): %v", err)
	}
	if len(owners) == 0 {
		t.Fatal("expected at least one owner from SOA RNAME, got none")
	}
	email := owners[0].GetId()
	if email == "" {
		t.Error("owner Id (email) is empty")
	}
	t.Logf("SOA owner: %s", email)
}

// TestIdentifyServer_DNSFallback verifies that an IdentifierServer with no
// OwnerStore but a DNS resolver returns an owner from SOA for a live domain.
func TestIdentifyServer_DNSFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := identifier.NewIdentifierServer(
		identifier.WithResourceResolver(dnsresolver.New()),
	)
	owner, err := srv.Identify(ctx, &pb.Resource{
		Type: dnsresolver.DomainResourceType,
		Name: "accretional.com",
	})
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if owner.GetId() == "" {
		t.Error("owner Id is empty")
	}
	t.Logf("owner via DNS: %s", owner.GetId())
}

// TestIdentifyServer_UnknownTypeNotFound verifies that a server with only a
// DNS resolver returns NotFound for a resource type it cannot handle.
func TestIdentifyServer_UnknownTypeNotFound(t *testing.T) {
	ctx := context.Background()
	srv := identifier.NewIdentifierServer(
		identifier.WithResourceResolver(dnsresolver.New()),
	)
	_, err := srv.Identify(ctx, &pb.Resource{Type: "other/Type", Name: "whatever"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}
