package identifier_test

import (
	"context"
	"testing"

	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthority_ReturnsConfiguredNames(t *testing.T) {
	srv := identifier.NewIdentifierServer(
		identifier.WithAuthority("example.com", "alice"),
	)

	resp, err := srv.Authority(context.Background(), &pb.Identity{})
	if err != nil {
		t.Fatalf("Authority() error: %v", err)
	}
	if resp.GetName() != "example.com" {
		t.Errorf("Name = %q, want %q", resp.GetName(), "example.com")
	}
	la := resp.GetLocalAuthority()
	if la == nil {
		t.Fatal("LocalAuthority is nil")
	}
	if la.GetName() != "alice" {
		t.Errorf("LocalAuthority.Name = %q, want %q", la.GetName(), "alice")
	}
}

func TestAuthenticate_NilHandlerReturnsUnimplemented(t *testing.T) {
	srv := identifier.NewIdentifierServer() // no WithAuthHandler

	stream := &fakeStream{}
	err := srv.Authenticate(stream)
	if err == nil {
		t.Fatal("expected error from Authenticate with nil handler, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want %v", status.Code(err), codes.Unimplemented)
	}
}

func TestIdentify_ReturnsUnimplemented(t *testing.T) {
	srv := identifier.NewIdentifierServer()

	_, err := srv.Identify(context.Background(), &pb.Resource{})
	if err == nil {
		t.Fatal("expected error from Identify, got nil")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want %v", status.Code(err), codes.Unimplemented)
	}
}
