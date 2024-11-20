package connector

import (
	"context"
	"os"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/require"
)

var (
	vaultHost  = os.Getenv("BATON_X_VAULT_HOST")
	vaultToken = os.Getenv("BATON_X_VAULT_TOKEN")
	ctxTest    = context.Background()
)

func getClientForTesting(ctx context.Context) (*client.HCPClient, error) {
	fsClient := client.NewClient()
	fsClient.WithBearerToken(vaultToken)
	return client.New(ctx, fsClient)
}

func TestUsersBuilderList(t *testing.T) {
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest)
	require.Nil(t, err)

	u := &userBuilder{
		resourceType: userResourceType,
		client:       cliTest,
	}
	var token = "{}"
	for token != "" {
		_, tk, _, err := u.List(ctxTest, &v2.ResourceId{}, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		token = tk
	}
}

func TestPolicyBuilderList(t *testing.T) {
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest)
	require.Nil(t, err)

	p := &policyBuilder{
		resourceType: policyResourceType,
		client:       cliTest,
	}
	var token = "{}"
	for token != "" {
		_, tk, _, err := p.List(ctxTest, &v2.ResourceId{}, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		token = tk
	}
}
