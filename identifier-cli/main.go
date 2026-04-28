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
	"google.golang.org/grpc/credentials/insecure"
)

var (
	flagServer   = flag.String("server", "localhost:9090", "gRPC server address")
	flagLogin    = flag.Bool("login", false, "Sign in via AuthKit web flow (opens browser)")
	flagClientID = flag.String("workos_client", os.Getenv("WORKOS_CLIENT_ID"), "WorkOS client ID for device auth")
	flagToken    = flag.String("token", "", "Send a pre-existing access token (or OTP secret) directly")
)

func main() {
	flag.Parse()

	serverAddr := *flagServer

	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", serverAddr, err)
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

	res, err := login.Run(context.Background(), idClient, serverAddr, *flagToken, clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	_ = res
}
