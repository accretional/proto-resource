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

func (s *identifierServer) Authority(ctx context.Context, req *pb.Identity) (*pb.Identity, error) {
	return &pb.Identity{
		Id:   "0",
		Name: s.authorityName,
		Provider: &pb.Identity_LocalAuthority{
			LocalAuthority: &pb.Identity{
				Id:   "system",
				Name: s.ownerName,
			},
		},
	}, nil
}

func (s *identifierServer) Identify(ctx context.Context, req *pb.Resource) (*pb.Identity, error) {
	return nil, status.Error(codes.Unimplemented, "Identify not yet implemented")
}
