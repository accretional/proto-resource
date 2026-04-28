package flows

import (
	"fmt"
	"io"

	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
)

// WorkOSToken sends an existing access token to the server and waits
// for an authenticated Resource back.
type WorkOSToken struct {
	AccessToken string
	UserName    string
}

func (f *WorkOSToken) Run(stream grpc.BidiStreamingClient[pb.Identity, pb.Resource]) (*pb.Resource, error) {
	err := stream.Send(&pb.Identity{
		Name: f.UserName,
		Provider: &pb.Identity_Secret{
			Secret: f.AccessToken,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("sending token: %w", err)
	}
	stream.CloseSend()

	res, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("server closed without responding")
		}
		return nil, fmt.Errorf("receiving auth result: %w", err)
	}

	return res, nil
}
