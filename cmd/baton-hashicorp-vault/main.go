package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/conductorone/baton-hashicorp-vault/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	version       = "dev"
	connectorName = "baton-hashicorp-vault"
)

func main() {
	ctx := context.Background()
	_, cmd, err := config.DefineConfiguration(
		ctx,
		connectorName,
		getConnector,
		Configurations,
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

func getConnector(ctx context.Context, cfg *viper.Viper) (types.ConnectorServer, error) {
	var (
		hcpClient = client.NewClient()
		token     = cfg.GetString(VaultTokenField.GetName())
		host      = cfg.GetString(VaultHostField.GetName())
	)
	l := ctxzap.Extract(ctx)
	err := hcpClient.WithAddress(host)
	if err != nil {
		return nil, err
	}

	hcpClient.WithBearerToken(token)
	cb, err := connector.New(ctx,
		token,
		host,
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
