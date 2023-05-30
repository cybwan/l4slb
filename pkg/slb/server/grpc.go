package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	maxStreams              = 100000
	streamKeepAliveDuration = 60 * time.Second
)

// GRPCServer is a construct to run gRPC servers
type GRPCServer struct {
	name   string
	server *grpc.Server
}

// NewGrpc creates a new gRPC server
func NewGrpc(serverName string, port int) (*GRPCServer, net.Listener, error) {
	log.Info().Msgf("Setting up %s gRPC server...", serverName)
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error().Err(err).Msgf("Error starting %s gRPC server on %s", serverName, addr)
		return nil, nil, err
	}

	log.Debug().Msgf("Parameters for %s gRPC server: MaxConcurrentStreams=%d;  KeepAlive=%+v", serverName, maxStreams, streamKeepAliveDuration)

	s := &GRPCServer{
		name: serverName,
	}

	grpcOptions := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(maxStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: streamKeepAliveDuration,
		}),
	}

	s.server = grpc.NewServer(grpcOptions...)
	return s, lis, nil
}

// GetServer returns the gRPC server
func (s *GRPCServer) GetServer() *grpc.Server {
	return s.server
}

// GrpcServe starts the gRPC server passed.
func (s *GRPCServer) GrpcServe(ctx context.Context, cancel context.CancelFunc, lis net.Listener, errorCh chan interface{}) error {
	log.Info().Str("grpc", s.name).Msgf("Starting server on: %s", lis.Addr())
	go func() {
		if err := s.server.Serve(lis); err != nil {
			log.Error().Str("grpc", s.name).Err(err).Msg("error serving gRPC request")
			if errorCh != nil {
				errorCh <- err
			}
		}
		cancel()
	}()

	go func() {
		<-ctx.Done()

		log.Info().Str("grpc", s.name).Msg("gracefully stopping gRPC server")
		s.server.GracefulStop()
		log.Info().Str("grpc", s.name).Msgf("exiting gRPC server")
	}()
	return nil
}
