package connector

import (
	"context"
	"io"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Connector struct {
	client *client.HCPClient
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client),
		newRoleBuilder(d.client),
		newPolicyBuilder(d.client),
		newSecretBuilder(d.client),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (d *Connector) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "HashiCorp Connector",
		Description: "Connector syncing users, roles and secrets from HashiCorp.",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, token, host string, hcpClient *client.HCPClient) (*Connector, error) {
	var err error
	if token != "" && host != "" {
		hcpClient, err = client.New(ctx, hcpClient)
		if err != nil {
			return nil, err
		}

		err = hcpClient.EnableAuthMethod(ctx, "approle", client.ApproleAuthEndpoint)
		if err != nil {
			return nil, err
		}

		err = hcpClient.EnableAuthMethod(ctx, "userpass", client.UserAuthEndpoint)
		if err != nil {
			return nil, err
		}
	}

	return &Connector{
		client: hcpClient,
	}, nil
}
