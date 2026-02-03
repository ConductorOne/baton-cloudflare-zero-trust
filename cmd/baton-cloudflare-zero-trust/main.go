package main

import (
	"context"

	"github.com/conductorone/baton-cloudflare-zero-trust/pkg/connector"
	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var version = "dev"

func main() {
	ctx := context.Background()
	config.RunConnector(
		ctx,
		"baton-cloudflare-zero-trust",
		version,
		cfg.Config,
		connector.New,
		connectorrunner.WithDefaultCapabilitiesConnectorBuilder(&connector.Connector{}),
	)
}
