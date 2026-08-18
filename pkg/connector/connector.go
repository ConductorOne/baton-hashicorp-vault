package connector

import (
	"context"
	"fmt"
	"io"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	cfg "github.com/conductorone/baton-hashicorp-vault/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Connector struct {
	client *client.HCPClient
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(_ context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newUserBuilder(d.client),
		newRoleBuilder(d.client),
		newPolicyBuilder(d.client),
		newSecretBuilder(d.client),
		newAuthMethodBuilder(d.client),
		newGroupBuilder(d.client),
		newEntityBuilder(d.client),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (d *Connector) Asset(_ context.Context, _ *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "HashiCorp Connector",
		Description: "Connector syncing users, roles and secrets from HashiCorp.",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	if err := d.client.LookupSelfToken(ctx); err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: invalid Vault credentials: %w", err)
	}

	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, config *cfg.HashicorpVault, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	hcpClient := client.NewClient()

	err := hcpClient.WithAddress(config.VaultHost)
	if err != nil {
		return nil, nil, err
	}

	if config.VaultToken != "" {
		hcpClient.WithBearerToken(config.VaultToken)
	} else {
		hcpClient.WithAppRole(config.RoleId, config.SecretId)
	}

	hcpClient.WithSkipMountBootstrap(config.SkipMountBootstrap)

	if hcpClient.IsConfigured() {
		hcpClient, err = client.New(ctx, hcpClient)
		if err != nil {
			return nil, nil, err
		}
	}

	return &Connector{
		client: hcpClient,
	}, nil, nil
}
