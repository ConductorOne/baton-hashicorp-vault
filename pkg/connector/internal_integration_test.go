package connector

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/conductorone/baton-hashicorp-vault/pkg/namegenerator"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/require"
)

var (
	vaultHost  = os.Getenv("BATON_X_VAULT_HOST")
	vaultToken = os.Getenv("BATON_X_VAULT_TOKEN")
	ctxTest    = context.Background()
)

func getClientForTesting(ctx context.Context, host string) (*client.HCPClient, error) {
	hcpClient := client.NewClient()
	hcpClient.WithBearerToken(vaultToken)
	_, err := hcpClient.WithAddress(host)
	if err != nil {
		return nil, err
	}

	hcpClient, err = client.New(ctx, hcpClient)
	if err != nil {
		return nil, err
	}

	err = hcpClient.EnableAuthMethod(ctx, "approle", client.ApproleAuthEndpoint)
	if err != nil {
		return hcpClient, err
	}

	err = hcpClient.EnableAuthMethod(ctx, "userpass", client.UserAuthEndpoint)
	if err != nil {
		return hcpClient, err
	}

	return hcpClient, nil
}

func TestUsersBuilderList(t *testing.T) {
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
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

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
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

func TestRoleBuilderList(t *testing.T) {
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)

	r := &roleBuilder{
		resourceType: roleResourceType,
		client:       cliTest,
	}
	var token = "{}"
	for token != "" {
		_, tk, _, err := r.List(ctxTest, &v2.ResourceId{}, &pagination.Token{
			Token: token,
		})
		require.Nil(t, err)
		token = tk
	}
}

func TestAddUsers(t *testing.T) {
	var count = 10
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)

	for i := 0; i < count; i++ {
		seed := time.Now().UTC().UnixNano()
		nameGenerator := namegenerator.NewNameGenerator(seed)
		name, err := nameGenerator.Generate()
		require.Nil(t, err)
		cli, err := client.New(context.Background(), cliTest)
		require.Nil(t, err)
		code, err := cli.AddUsers(context.Background(), http.MethodPost, client.UsersEndpoint, name)
		require.Nil(t, err)
		require.Equal(t, code, http.StatusNoContent)
	}
}

func TestAddRoles(t *testing.T) {
	var count = 10
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)

	for i := 0; i < count; i++ {
		seed := time.Now().UTC().UnixNano()
		nameGenerator := namegenerator.NewNameGenerator(seed)
		name, err := nameGenerator.Generate()
		require.Nil(t, err)
		cli, err := client.New(context.Background(), cliTest)
		require.Nil(t, err)
		code, err := cli.AddRoles(context.Background(), http.MethodPost, client.RolesEndpoint, name)
		require.Nil(t, err)
		require.Equal(t, code, http.StatusNoContent)
	}
}
