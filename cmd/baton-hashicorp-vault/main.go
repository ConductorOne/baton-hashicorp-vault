package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/conductorone/baton-hashicorp-vault/pkg/connector"
	configSchema "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()
	_, cmd, err := configSchema.DefineConfiguration(
		ctx,
		"baton-hashicorp-vault",
		getConnector,
		config.Configuration,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *config.Hashicorpvault) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	hcpClient := client.NewClient()

	err := hcpClient.WithAddress(cfg.VaultHost)
	if err != nil {
		return nil, err
	}

	hcpClient.WithBearerToken(cfg.VaultToken)
	cb, err := connector.New(ctx,
		cfg.VaultToken,
		cfg.VaultHost,
		hcpClient,
	)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
