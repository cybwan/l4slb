package main

import (
	"context"
	"flag"
	"github.com/cybwan/l4slb/pkg/logger"
	"github.com/cybwan/l4slb/pkg/signals"
	"github.com/cybwan/l4slb/pkg/slb/httpserver"
	"github.com/cybwan/l4slb/pkg/slb/server"
	"github.com/cybwan/l4slb/pkg/version"
)

var (
	eth  = flag.String("default_route_device", "ens33", "The server default route device")
	port = flag.Int("port", 50051, "The server port")
	log  = logger.New("flomesh-lb-server")
)

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	stop := signals.RegisterExitHandlers(cancel)

	ctrlServer := server.NewL4SlbControlServer()
	release, err := ctrlServer.Start(ctx, cancel, *eth, *port)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to start L4Slb Control server")
	}

	httpServer := httpserver.NewHTTPServer(80)
	httpServer.AddHandler("/version", version.GetVersionHandler())
	// Start HTTP server
	if err := httpServer.Start(); err != nil {
		log.Fatal().Err(err).Msgf("Failed to start L4Slb HTTP server")
	}

	<-stop
	release()
	cancel()
	log.Info().Msgf("Stopping L4Slb Controller %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
}
