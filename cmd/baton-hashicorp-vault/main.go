package main

import (
	"context"

	cfg "github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/conductorone/baton-hashicorp-vault/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var (
	version       = "dev"
	connectorName = "baton-hashicorp-vault"
)

func main() {
	ctx := context.Background()
	config.RunConnector(
		ctx,
		connectorName,
		version,
		cfg.Config,
		connector.New,
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(&connector.Connector{}),
	)
}

/*
func main() {
	ctx := context.Background()
	_, cmd, err := config.DefineConfiguration(
		ctx,
		connectorName,
		getConnector,
		cfg.Configurations,
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
		token     = cfg.GetString(config2.VaultTokenField.GetName())
		roleID    = cfg.GetString(config2.RoleIDField.GetName())
		secretID  = cfg.GetString(config2.SecretIDField.GetName())
		host      = cfg.GetString(config2.VaultHostField.GetName())
	)
	l := ctxzap.Extract(ctx)
	err := hcpClient.WithAddress(host)
	if err != nil {
		return nil, err
	}

	if token != "" {
		hcpClient.WithBearerToken(token)
	} else {
		hcpClient.WithAppRole(roleID, secretID)
	}

	cb, err := connector.New(ctx, hcpClient)
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
*/
