package otp_test

import (
	"context"
	"io"
	"testing"

	"github.com/accretional/proto-resource/auth/otp"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// fakeStream is a minimal mock of grpc.BidiStreamingServer[pb.Identity, pb.Resource].
type fakeStream struct {
	sent []*pb.Resource
	recv []*pb.Identity
	pos  int
}

func (f *fakeStream) Send(r *pb.Resource) error {
	f.sent = append(f.sent, r)
	return nil
}

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

func TestNewSystem_TokenNonEmpty(t *testing.T) {
	p := otp.NewSystem()
	if p.Token() == "" {
		t.Fatal("NewSystem() produced empty token")
	}
}

func TestNewSystem_TokenIsUUID(t *testing.T) {
	p1 := otp.NewSystem()
	p2 := otp.NewSystem()
	if p1.Token() == p2.Token() {
		t.Error("two NewSystem() calls produced the same token")
	}
}

func TestMatch_CorrectSecret(t *testing.T) {
	p := otp.New("test", "secret123")
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: "secret123"}}
	if !p.Match(id) {
		t.Error("Match returned false for correct secret")
	}
}

func TestMatch_WrongSecret(t *testing.T) {
	p := otp.New("test", "secret123")
	if p.Match(&pb.Identity{Provider: &pb.Identity_Secret{Secret: "wrong"}}) {
		t.Error("Match returned true for wrong secret")
	}
}

func TestMatch_EmptyIdentity(t *testing.T) {
	p := otp.New("test", "secret123")
	if p.Match(&pb.Identity{}) {
		t.Error("Match returned true for empty identity")
	}
}

func TestLogin_ReturnsSystemResource(t *testing.T) {
	p := otp.New("system", "token")
	res, err := p.Login()
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}
	if res.GetName() != "system" {
		t.Errorf("Name = %q, want %q", res.GetName(), "system")
	}
	if res.GetType() != "identity.system" {
		t.Errorf("Type = %q, want %q", res.GetType(), "identity.system")
	}
}

func TestHandle_SendsExactlyOneResource(t *testing.T) {
	p := otp.New("system", "token")
	stream := &fakeStream{}
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: "token"}}

	if err := p.Handle(id, stream); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d resources, want 1", len(stream.sent))
	}
}

func TestHandle_ResourceType(t *testing.T) {
	p := otp.New("system", "token")
	stream := &fakeStream{}

	p.Handle(&pb.Identity{}, stream) //nolint:errcheck

	res := stream.sent[0]
	if res.GetType() != "identity.authenticated" {
		t.Errorf("Type = %q, want %q", res.GetType(), "identity.authenticated")
	}
}

func TestHandle_OwnersContainOTPProvider(t *testing.T) {
	p := otp.New("system", "token")
	stream := &fakeStream{}

	p.Handle(&pb.Identity{}, stream) //nolint:errcheck

	res := stream.sent[0]
	if len(res.GetOwners()) != 1 {
		t.Fatalf("len(Owners) = %d, want 1", len(res.GetOwners()))
	}
	if got := res.GetOwners()[0].GetType(); got != "otp.provider" {
		t.Errorf("Owners[0].Type = %q, want %q", got, "otp.provider")
	}
}
