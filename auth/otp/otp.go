package otp

import (
	"fmt"
	"log"

	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// Provider implements both identifier.LoginProvider (for boot-time
// authentication) and identifier.AuthFlow (for Authenticate RPC).
type Provider struct {
	name  string
	token string
}

// NewSystem creates a system OTP provider with a generated token.
// The token is printed to stdout for the operator.
func NewSystem() *Provider {
	token := uuid.NewString()
	fmt.Printf("[otp] system token: %s\n", token)
	return &Provider{name: "system", token: token}
}

// New creates an OTP provider with the given name and token.
func New(name, token string) *Provider {
	return &Provider{name: name, token: token}
}

// Token returns the provider's token value.
func (p *Provider) Token() string { return p.token }

// --- identifier.LoginProvider ---

func (p *Provider) Name() string { return p.name }

// Login returns immediately with a Resource representing the system identity.
func (p *Provider) Login() (*pb.Resource, error) {
	return &pb.Resource{
		Name: p.name,
		Type: "identity.system",
	}, nil
}

// --- identifier.AuthFlow ---

// Match returns true when the client's secret matches this provider's token.
func (p *Provider) Match(first *pb.Identity) bool {
	return first.GetSecret() == p.token
}

// Handle validates the token and returns an authenticated Resource.
func (p *Provider) Handle(first *pb.Identity, stream grpc.BidiStreamingServer[pb.Identity, pb.Resource]) error {
	log.Printf("[otp] %s authenticated via token", p.name)

	res := &pb.Resource{
		Name: p.name,
		Type: "identity.authenticated",
		Owners: []*pb.Resource{
			{Name: p.name, Type: "otp.provider"},
		},
	}
	return stream.Send(res)
}

// Compile-time interface checks.
var _ identifier.LoginProvider = (*Provider)(nil)
var _ identifier.AuthFlow = (*Provider)(nil)
