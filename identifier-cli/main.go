package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/accretional/proto-resource/identifier-cli/login"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var (
	flagServer   = flag.String("server", "localhost:9090", "gRPC server address")
	flagLogin    = flag.Bool("login", false, "Sign in via AuthKit web flow (opens browser)")
	flagClientID = flag.String("workos_client", os.Getenv("WORKOS_CLIENT_ID"), "WorkOS client ID for device auth")
	flagToken    = flag.String("token", "", "Send a pre-existing access token (or OTP secret) directly")
	flagIdentify = flag.String("identify", "", "Domain FQDN to check ownership of after authenticating (e.g. example.com)")
)

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(*flagServer,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", *flagServer, err)
	}
	defer conn.Close()

	idClient := pb.NewIdentifierClient(conn)

	var clientID string
	if *flagLogin {
		clientID = *flagClientID
		if clientID == "" {
			fmt.Fprintln(os.Stderr, "WORKOS_CLIENT_ID must be set (or use -workos_client) for -login")
			os.Exit(1)
		}
	}

	res, err := login.Run(context.Background(), idClient, *flagServer, *flagToken, clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	if *flagIdentify == "" {
		return
	}

	// Ownership check: identify who owns the requested domain, then compare
	// against the authenticated user's email.
	fqdn := *flagIdentify
	ownerIdentity, err := idClient.Identify(context.Background(), &pb.Resource{
		Type: "proto-domain/Domain",
		Name: fqdn,
	})

	fmt.Printf("  Domain:  %s\n", fqdn)

	if err != nil {
		if status.Code(err) == codes.NotFound {
			fmt.Printf("  Owner:   (none registered)\n")
			fmt.Printf("  Access:  denied\n")
		} else {
			fmt.Fprintf(os.Stderr, "  Identify error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	authenticatedEmail := res.GetName()
	ownerEmail := ownerIdentity.GetId()

	fmt.Printf("  Owner:   %s\n", ownerEmail)
	if ownerEmail == authenticatedEmail {
		fmt.Printf("  Access:  granted\n")
	} else {
		fmt.Printf("  Access:  denied (you are %s)\n", authenticatedEmail)
	}
}
