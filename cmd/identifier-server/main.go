package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/accretional/proto-resource/auth/otp"
	authworkos "github.com/accretional/proto-resource/auth/workos"
	"github.com/accretional/proto-resource/identifier"
	flowworkos "github.com/accretional/proto-resource/identifier/authflows/workos"
	sqlitestore "github.com/accretional/proto-resource/identifier/sqlite"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
)

var (
	flagAddr = flag.String("addr", ":9090", "listen address")
	flagDB   = flag.String("db", "", "SQLite file for resource ownership (e.g. owners.db); omit to disable Identify")
)

func main() {
	// OTP must be registered before Init so it runs as a boot-time login provider.
	otpProvider := otp.NewSystem()
	identifier.RegisterLoginProvider(otpProvider)
	identifier.Init() // parses flags, pushes WorkOS flags into env, runs login providers

	// Build the auth flow list. OTP is first so its exact-token match takes
	// priority over the WorkOS token flow's broader "any secret" match.
	flows := []identifier.AuthFlow{otpProvider}

	apiKey := os.Getenv("WORKOS_API_KEY")
	clientID := os.Getenv("WORKOS_CLIENT_ID")
	if apiKey != "" && clientID != "" {
		wc, err := authworkos.NewClient(apiKey, clientID)
		if err != nil {
			log.Fatalf("workos client: %v", err)
		}
		flows = append(flows,
			&flowworkos.Token{Client: wc},
			&flowworkos.Invite{Client: wc, ServiceName: identifier.RootAuthority()},
		)
		log.Printf("[identifier-server] WorkOS auth flows registered (authority=%s)", identifier.RootAuthority())
	}

	opts := []identifier.Option{
		identifier.WithAuthHandler(&identifier.AuthDispatcher{Flows: flows}),
	}

	if *flagDB != "" {
		store, err := sqlitestore.Open(*flagDB)
		if err != nil {
			log.Fatalf("open owner db %q: %v", *flagDB, err)
		}
		opts = append(opts, identifier.WithOwnerStore(store))
		log.Printf("[identifier-server] owner store: %s", *flagDB)
	}

	srv := identifier.NewIdentifierServer(opts...)

	grpcServer := grpc.NewServer()
	pb.RegisterIdentifierServer(grpcServer, srv)

	lis, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *flagAddr, err)
	}
	log.Printf("[identifier-server] listening on %s", *flagAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
