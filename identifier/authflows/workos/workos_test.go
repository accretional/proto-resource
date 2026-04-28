package workos_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	authworkos "github.com/accretional/proto-resource/auth/workos"
	flowworkos "github.com/accretional/proto-resource/identifier/authflows/workos"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// fakeStream is a pre-loaded mock of grpc.BidiStreamingServer[pb.Identity, pb.Resource].
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

// callbackStream drives each Recv via a function, letting the test inject
// input mid-flow — after the flow has already sent a magic-auth email and
// the human needs to provide the code from that specific send.
type callbackStream struct {
	sent    []*pb.Resource
	recvFns []func() (*pb.Identity, error)
	pos     int
}

func (s *callbackStream) Send(r *pb.Resource) error {
	s.sent = append(s.sent, r)
	return nil
}

func (s *callbackStream) Recv() (*pb.Identity, error) {
	if s.pos >= len(s.recvFns) {
		return nil, io.EOF
	}
	fn := s.recvFns[s.pos]
	s.pos++
	return fn()
}

func (s *callbackStream) SetHeader(metadata.MD) error  { return nil }
func (s *callbackStream) SendHeader(metadata.MD) error { return nil }
func (s *callbackStream) SetTrailer(metadata.MD)       {}
func (s *callbackStream) Context() context.Context     { return context.Background() }
func (s *callbackStream) SendMsg(any) error            { return nil }
func (s *callbackStream) RecvMsg(any) error            { return nil }

var _ grpc.BidiStreamingServer[pb.Identity, pb.Resource] = (*callbackStream)(nil)


func newClient(t *testing.T) *authworkos.Client {
	t.Helper()
	apiKey := os.Getenv("WORKOS_API_KEY")
	clientID := os.Getenv("WORKOS_CLIENT_ID")
	if apiKey == "" || clientID == "" {
		t.Skip("WORKOS_API_KEY and WORKOS_CLIENT_ID required")
	}
	c, err := authworkos.NewClient(apiKey, clientID)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// --- Match (unit, no API calls) ---

func TestTokenFlow_Match_NonEmptySecret(t *testing.T) {
	f := &flowworkos.Token{}
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: "some-token"}}
	if !f.Match(id) {
		t.Error("Token.Match returned false for non-empty secret")
	}
}

func TestTokenFlow_Match_EmptySecret(t *testing.T) {
	f := &flowworkos.Token{}
	if f.Match(&pb.Identity{}) {
		t.Error("Token.Match returned true for empty identity")
	}
}

func TestInviteFlow_Match_EmptySecret(t *testing.T) {
	f := &flowworkos.Invite{}
	if !f.Match(&pb.Identity{Name: "alice"}) {
		t.Error("Invite.Match returned false for identity with no secret")
	}
}

func TestInviteFlow_Match_NonEmptySecret(t *testing.T) {
	f := &flowworkos.Invite{}
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: "code"}}
	if f.Match(id) {
		t.Error("Invite.Match returned true when secret is set")
	}
}

// --- Token flow (requires WORKOS_TEST_ACCESS_TOKEN) ---

func TestTokenFlow_ValidToken(t *testing.T) {
	token := os.Getenv("WORKOS_TEST_ACCESS_TOKEN")
	if token == "" {
		t.Skip("WORKOS_TEST_ACCESS_TOKEN required")
	}
	c := newClient(t)
	flow := &flowworkos.Token{Client: c}
	stream := &fakeStream{}
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: token}}

	if err := flow.Handle(id, stream); err != nil {
		t.Fatalf("Token.Handle: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d resources, want 1", len(stream.sent))
	}
	res := stream.sent[0]
	if res.GetType() != "identity.authenticated" {
		t.Errorf("Type = %q, want %q", res.GetType(), "identity.authenticated")
	}
	if res.GetName() == "" {
		t.Error("authenticated resource has empty Name (expected email)")
	}
	if len(res.GetOwners()) == 0 || res.GetOwners()[0].GetType() != "workos.user_id" {
		t.Errorf("expected Owners[0].Type=workos.user_id, got %+v", res.GetOwners())
	}
	t.Logf("authenticated as %s", res.GetName())
}

func TestTokenFlow_InvalidToken(t *testing.T) {
	c := newClient(t)
	flow := &flowworkos.Token{Client: c}
	stream := &fakeStream{}
	id := &pb.Identity{Provider: &pb.Identity_Secret{Secret: "not.a.real.jwt"}}

	err := flow.Handle(id, stream)
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if len(stream.sent) != 0 {
		t.Errorf("expected no resources sent on error, got %d", len(stream.sent))
	}
}

// --- Invite flow ---

// TestInviteFlow_SendsMagicAuth verifies that Handle sends service_info and
// code_sent, and calls SendMagicAuth/CreateInvitation for the given email.
// Requires WORKOS_TEST_EMAIL; after running, check your inbox.
func TestInviteFlow_SendsMagicAuth(t *testing.T) {
	email := os.Getenv("WORKOS_TEST_EMAIL")
	if email == "" {
		t.Skip("WORKOS_TEST_EMAIL required")
	}
	if os.Getenv("WORKOS_TEST_INVITE_CODE") != "" {
		t.Skip("skipping send — WORKOS_TEST_INVITE_CODE already set, use TestInviteFlow_FullRoundTrip to verify it")
	}
	c := newClient(t)
	flow := &flowworkos.Invite{Client: c, ServiceName: "test-service"}

	stream := &fakeStream{
		recv: []*pb.Identity{
			{Id: email}, // step 2: client provides email
			// no code — Handle gets EOF and returns nil (clean close)
		},
	}

	first := &pb.Identity{Name: "tester"}
	if err := flow.Handle(first, stream); err != nil {
		t.Fatalf("Invite.Handle: %v", err)
	}

	if len(stream.sent) < 2 {
		t.Fatalf("expected at least 2 resources (service_info, code_sent), got %d", len(stream.sent))
	}
	if stream.sent[0].GetType() != "identity.service_info" {
		t.Errorf("sent[0].Type = %q, want identity.service_info", stream.sent[0].GetType())
	}
	if stream.sent[1].GetType() != "identity.code_sent" {
		t.Errorf("sent[1].Type = %q, want identity.code_sent", stream.sent[1].GetType())
	}
	t.Logf("magic auth / invitation triggered for %s — check your inbox", email)
}

// TestInviteFlow_FullRoundTrip completes the entire invite flow interactively.
// It drives Handle via a callbackStream: the email step is pre-set, but the
// code step prompts stdin AFTER Handle has sent the magic-auth email — so the
// code entered is the one from that specific send, not a stale pre-loaded value.
//
// Requires WORKOS_TEST_EMAIL and WORKOS_TEST_INTERACTIVE=1 (opt-in to avoid
// accidentally blocking automated test runs waiting for stdin input).
func TestInviteFlow_FullRoundTrip(t *testing.T) {
	email := os.Getenv("WORKOS_TEST_EMAIL")
	if email == "" {
		t.Skip("WORKOS_TEST_EMAIL required")
	}
	if os.Getenv("WORKOS_TEST_INTERACTIVE") != "1" {
		t.Skip("set WORKOS_TEST_INTERACTIVE=1 to run this test interactively")
	}

	c := newClient(t)
	flow := &flowworkos.Invite{Client: c, ServiceName: "test-service"}

	stdin := bufio.NewReader(os.Stdin)
	stream := &callbackStream{
		recvFns: []func() (*pb.Identity, error){
			// step 2: email
			func() (*pb.Identity, error) {
				return &pb.Identity{Id: email}, nil
			},
			// step 4: code — read from stdin after Handle has sent the email
			func() (*pb.Identity, error) {
				fmt.Printf("\n  Check %s for a magic-auth code and enter it: ", email)
				line, _ := stdin.ReadString('\n')
				code := strings.TrimSpace(line)
				return &pb.Identity{Provider: &pb.Identity_Secret{Secret: code}}, nil
			},
		},
	}

	first := &pb.Identity{Name: "tester"}
	if err := flow.Handle(first, stream); err != nil {
		t.Fatalf("Invite.Handle: %v", err)
	}

	if len(stream.sent) != 3 {
		t.Fatalf("expected 3 resources (service_info, code_sent, authenticated), got %d", len(stream.sent))
	}
	if stream.sent[0].GetType() != "identity.service_info" {
		t.Errorf("sent[0].Type = %q, want identity.service_info", stream.sent[0].GetType())
	}
	if stream.sent[1].GetType() != "identity.code_sent" {
		t.Errorf("sent[1].Type = %q, want identity.code_sent", stream.sent[1].GetType())
	}
	authRes := stream.sent[2]
	if authRes.GetType() != "identity.authenticated" {
		t.Errorf("sent[2].Type = %q, want identity.authenticated", authRes.GetType())
	}
	if authRes.GetName() == "" {
		t.Error("authenticated resource has empty Name")
	}
	if len(authRes.GetOwners()) == 0 || authRes.GetOwners()[0].GetType() != "workos.user_id" {
		t.Errorf("expected Owners[0].Type=workos.user_id, got %+v", authRes.GetOwners())
	}
	t.Logf("authenticated as %s (%s)", authRes.GetName(), authRes.GetOwners()[0].GetName())
}
