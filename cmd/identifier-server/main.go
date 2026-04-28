package main

import (
	"flag"
	"log"
	"net"

	"github.com/accretional/proto-resource/auth/otp"
	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc"
)

var flagAddr = flag.String("addr", ":9090", "listen address")

func main() {
	otpProvider := otp.NewSystem()
	identifier.RegisterLoginProvider(otpProvider)
	identifier.Init()

	dispatcher := &identifier.AuthDispatcher{
		Flows: []identifier.AuthFlow{otpProvider},
	}

	srv := identifier.NewIdentifierServer(
		identifier.WithAuthHandler(dispatcher),
	)

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
