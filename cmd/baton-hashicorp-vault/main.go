package main

import (
	"context"

	cfg "github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/conductorone/baton-hashicorp-vault/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var (
	version = "dev"
)

func main() {
	ctx := context.Background()
	config.RunConnector(
		ctx,
		"baton-hashicorp-vault",
		version,
		cfg.Config,
		connector.New,
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(&connector.Connector{}),
	)
}
