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
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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

// Validate verifies the Vault token with lookup-self. Invalid credentials fail
// validation; missing sync capabilities only produce warnings so partial syncs
// remain possible.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	tokenInfo, err := d.client.LookupSelf(ctx)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: invalid Vault credentials: %w", err)
	}

	logger := ctxzap.Extract(ctx)
	logger.Info("baton-hashicorp-vault: validated Vault token",
		zap.String("display_name", tokenInfo.DisplayName),
		zap.Strings("policies", tokenInfo.Policies),
		zap.String("namespace_path", tokenInfo.NamespacePath),
		zap.Int("ttl", tokenInfo.TTL),
		zap.Bool("renewable", tokenInfo.Renewable),
	)

	paths := make([]string, 0, len(requiredCapabilities))
	for _, required := range requiredCapabilities {
		paths = append(paths, required.path)
	}
	capabilities, err := d.client.CapabilitiesSelf(ctx, paths)
	if err != nil {
		logger.Warn("baton-hashicorp-vault: could not verify token capabilities; the sync will skip anything the token cannot read", zap.Error(err))
		return nil, nil
	}

	namespace := d.client.Namespace()
	if namespace == "" {
		namespace = tokenInfo.NamespacePath
	}
	missing := missingCapabilities(capabilities)
	for _, resourceType := range missing {
		for _, required := range requiredCapabilities {
			if required.resourceType != resourceType {
				continue
			}
			logger.Warn("baton-hashicorp-vault: token lacks required capability; resource type will be synced as empty",
				zap.String("path", required.path),
				zap.String("missing_capability", required.capability),
				zap.String("namespace", namespace),
				zap.String("consequence", "the "+resourceType+" resource type will be synced as empty"),
			)
			break
		}
	}
	return nil, nil
}

// Close clears HTTP caches maintained by the Baton SDK.
func (d *Connector) Close(ctx context.Context) error {
	return uhttp.ClearCaches(ctx)
}

// New returns a new instance of the connector.
func New(ctx context.Context, config *cfg.HashicorpVault, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	hcpClient := client.NewClient()
	hcpClient.WithNamespace(config.VaultNamespace)

	if config.VaultToken != "" {
		hcpClient.WithBearerToken(config.VaultToken)
	} else {
		hcpClient.WithAppRole(config.RoleId, config.SecretId)
	}

	if !hcpClient.IsConfigured() {
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: no Vault credentials configured: set --vault-token or --role-id and --secret-id")
	}

	err := hcpClient.WithAddress(config.VaultHost)
	if err != nil {
		return nil, nil, err
	}

	hcpClient, err = client.New(ctx, hcpClient)
	if err != nil {
		return nil, nil, err
	}

	return &Connector{
		client: hcpClient,
	}, nil, nil
}
