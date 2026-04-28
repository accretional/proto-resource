package login

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/accretional/proto-resource/identifier-cli/login/flows"
	"github.com/accretional/proto-resource/pb"
)

const streamTimeout = 5 * time.Minute

// Run executes the appropriate login flow against the Identifier service.
//
// Flow selection:
//   - clientID != ""    → web auth (AuthKit device flow in browser)
//   - accessToken != "" → token flow (send existing token)
//   - otherwise         → invite flow (email + code)
func Run(ctx context.Context, client pb.IdentifierClient, serverAddr string, accessToken string, clientID string) (*pb.Resource, error) {
	authority, err := client.Authority(ctx, &pb.Identity{})
	if err != nil {
		return nil, fmt.Errorf("querying server authority: %w", err)
	}

	svcName := authority.GetName()
	svcOwner := ""
	if la := authority.GetLocalAuthority(); la != nil {
		svcOwner = la.GetName()
	}

	fmt.Println()
	fmt.Printf("  Server:    %s\n", serverAddr)
	fmt.Printf("  Authority: %s\n", svcName)
	if svcOwner != "" {
		fmt.Printf("  Owner:     %s\n", svcOwner)
	}
	hostname, _ := os.Hostname()
	if hostname != "" {
		fmt.Printf("  Client:    %s\n", hostname)
	}
	fmt.Println()

	var flow flows.ClientFlow
	switch {
	case clientID != "":
		fmt.Printf("  Signing in to %s via browser...\n\n", svcName)
		flow = &flows.WorkOSWeb{
			Client: &flows.DeviceAuthClient{ClientID: clientID},
		}

	case accessToken != "":
		fmt.Printf("  You are about to send your access credentials to %s.\n", serverAddr)
		fmt.Print("  Proceed? [Y/n] ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "" && confirm != "y" && confirm != "Y" {
			return nil, fmt.Errorf("user declined")
		}
		fmt.Println()
		flow = &flows.WorkOSToken{AccessToken: accessToken}

	default:
		flow = &flows.WorkOSInvite{}
	}

	streamCtx, cancel := context.WithTimeout(ctx, streamTimeout)
	defer cancel()

	stream, err := client.Authenticate(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("opening authenticate stream: %w", err)
	}

	res, err := flow.Run(stream)
	if err != nil {
		return nil, err
	}

	fmt.Printf("  Logged in as %s\n\n", res.GetName())
	return res, nil
}
