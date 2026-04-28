package identifier

import (
	"context"

	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthenticateHandler is the interface for pluggable authentication
// dispatch. It is defined here so that external packages can implement
// it without creating an import cycle.
type AuthenticateHandler interface {
	Handle(stream grpc.BidiStreamingServer[pb.Identity, pb.Resource]) error
}

type identifierServer struct {
	pb.UnimplementedIdentifierServer
	authHandler   AuthenticateHandler
	ownerStore    OwnerStore
	authorityName string
	ownerName     string
}

// NewIdentifierServer creates an IdentifierServer.
func NewIdentifierServer(opts ...Option) pb.IdentifierServer {
	s := &identifierServer{
		authorityName: RootAuthority(),
		ownerName:     RootIdentity(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Option configures the identifier server.
type Option func(*identifierServer)

// WithAuthHandler sets the authentication handler.
func WithAuthHandler(h AuthenticateHandler) Option {
	return func(s *identifierServer) {
		s.authHandler = h
	}
}

// WithAuthority sets the authority and owner names for the server.
func WithAuthority(authority, owner string) Option {
	return func(s *identifierServer) {
		s.authorityName = authority
		s.ownerName = owner
	}
}

func (s *identifierServer) Authenticate(stream grpc.BidiStreamingServer[pb.Identity, pb.Resource]) error {
	if s.authHandler == nil {
		return status.Error(codes.Unimplemented, "Authenticate not configured")
	}
	return s.authHandler.Handle(stream)
}

func (s *identifierServer) localAuthority() *pb.Identity {
	return &pb.Identity{
		Id:   "0",
		Name: s.authorityName,
		Provider: &pb.Identity_LocalAuthority{
			LocalAuthority: &pb.Identity{
				Id:   "system",
				Name: s.ownerName,
			},
		},
	}
}

func (s *identifierServer) Authority(ctx context.Context, req *pb.Identity) (*pb.Identity, error) {
	name := req.GetName()

	// Empty request or the server's own authority name: always local.
	if name == "" || name == s.authorityName {
		return s.localAuthority(), nil
	}

	if s.ownerStore != nil {
		local, err := s.ownerStore.IsLocal(ctx, name)
		if err != nil {
			return nil, err
		}
		if local {
			return s.localAuthority(), nil
		}
		// Name is not locally registered. Remote authority discovery is not
		// yet implemented; callers should treat this as "authority unknown".
		return nil, status.Errorf(codes.NotFound,
			"no local authority for %q; remote authority lookup not yet implemented", name)
	}

	// No owner store configured: single-server mode, claim local for everything.
	return s.localAuthority(), nil
}

func (s *identifierServer) Identify(ctx context.Context, req *pb.Resource) (*pb.Identity, error) {
	// The "system" resource resolves to this service's own identity.
	if req.GetName() == "system" {
		return s.localAuthority(), nil
	}
	if s.ownerStore == nil {
		return nil, status.Error(codes.Unimplemented, "Identify not configured")
	}
	owners, err := s.ownerStore.Owners(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(owners) == 0 {
		return nil, status.Errorf(codes.NotFound, "no owner for %s/%s", req.GetType(), req.GetName())
	}
	return owners[0], nil
}
