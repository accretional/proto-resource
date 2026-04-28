package identifier_test

import (
	"context"
	"io"
	"testing"

	"github.com/accretional/proto-resource/identifier"
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

// recordingFlow records the first identity it receives and sends one Resource.
type recordingFlow struct {
	matchFn   func(*pb.Identity) bool
	received  *pb.Identity
	sendToken string
}

func (r *recordingFlow) Match(first *pb.Identity) bool {
	return r.matchFn(first)
}

func (r *recordingFlow) Handle(first *pb.Identity, stream grpc.BidiStreamingServer[pb.Identity, pb.Resource]) error {
	r.received = first
	return stream.Send(&pb.Resource{Type: r.sendToken})
}

var _ identifier.AuthFlow = (*recordingFlow)(nil)

func TestAuthDispatcher_DispatchesToMatchingFlow(t *testing.T) {
	flow := &recordingFlow{
		matchFn:   func(*pb.Identity) bool { return true },
		sendToken: "matched",
	}
	d := &identifier.AuthDispatcher{Flows: []identifier.AuthFlow{flow}}
	stream := &fakeStream{recv: []*pb.Identity{{Name: "alice"}}}

	if err := d.Handle(stream); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetType() != "matched" {
		t.Errorf("unexpected sent resources: %+v", stream.sent)
	}
}

func TestAuthDispatcher_PassesFirstIdentity(t *testing.T) {
	flow := &recordingFlow{matchFn: func(*pb.Identity) bool { return true }}
	d := &identifier.AuthDispatcher{Flows: []identifier.AuthFlow{flow}}
	want := &pb.Identity{Name: "bob"}
	stream := &fakeStream{recv: []*pb.Identity{want}}

	d.Handle(stream) //nolint:errcheck

	if flow.received.GetName() != "bob" {
		t.Errorf("received Name = %q, want %q", flow.received.GetName(), "bob")
	}
}

func TestAuthDispatcher_SkipsNonMatchingFlows(t *testing.T) {
	skip := &recordingFlow{matchFn: func(*pb.Identity) bool { return false }}
	hit := &recordingFlow{
		matchFn:   func(*pb.Identity) bool { return true },
		sendToken: "hit",
	}
	d := &identifier.AuthDispatcher{Flows: []identifier.AuthFlow{skip, hit}}
	stream := &fakeStream{recv: []*pb.Identity{{Name: "carol"}}}

	if err := d.Handle(stream); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	if skip.received != nil {
		t.Error("non-matching flow should not have its Handle called")
	}
	if hit.received == nil {
		t.Error("matching flow Handle was not called")
	}
}

func TestAuthDispatcher_ErrorWhenNoFlowMatches(t *testing.T) {
	d := &identifier.AuthDispatcher{Flows: []identifier.AuthFlow{
		&recordingFlow{matchFn: func(*pb.Identity) bool { return false }},
	}}
	stream := &fakeStream{recv: []*pb.Identity{{Name: "dave"}}}

	if err := d.Handle(stream); err == nil {
		t.Error("expected error when no flow matches, got nil")
	}
}

func TestAuthDispatcher_ErrorOnEmptyStream(t *testing.T) {
	d := &identifier.AuthDispatcher{Flows: []identifier.AuthFlow{
		&recordingFlow{matchFn: func(*pb.Identity) bool { return true }},
	}}
	stream := &fakeStream{recv: []*pb.Identity{}} // EOF immediately

	// io.EOF on the first Recv returns nil (stream closed cleanly).
	if err := d.Handle(stream); err != nil {
		t.Errorf("empty stream should return nil, got: %v", err)
	}
}
