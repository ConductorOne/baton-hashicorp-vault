package connector

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/conductorone/baton-hashicorp-vault/pkg/namegenerator"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
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
	var count = 100
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)
	cli, err := client.New(context.Background(), cliTest)
	require.Nil(t, err)

	for i := 0; i < count; i++ {
		seed := time.Now().UTC().UnixNano()
		nameGenerator := namegenerator.NewNameGenerator(seed)
		name, err := nameGenerator.Generate()
		require.Nil(t, err)
		code, err := cli.AddUsers(context.Background(), name)
		require.Nil(t, err)
		require.Equal(t, code, http.StatusNoContent)
	}
}

func TestAddRoles(t *testing.T) {
	var count = 100
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)
	cli, err := client.New(context.Background(), cliTest)
	require.Nil(t, err)
	for i := 0; i < count; i++ {
		seed := time.Now().UTC().UnixNano()
		nameGenerator := namegenerator.NewNameGenerator(seed)
		name, err := nameGenerator.Generate()
		require.Nil(t, err)
		code, err := cli.AddRoles(context.Background(), name)
		require.Nil(t, err)
		require.Equal(t, code, http.StatusNoContent)
	}
}

func TestGroupGrant(t *testing.T) {
	var roleEntitlement string
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
	require.Nil(t, err)

	grantEntitlement := "policy:root:assigned"
	grantPrincipalType := "user"
	grantPrincipal := "adleyberry"
	_, data, err := parseEntitlementID(grantEntitlement)
	require.Nil(t, err)
	require.NotNil(t, data)

	roleEntitlement = data[2]
	resource, err := getPolicyForTesting(ctxTest, data[1], "default")
	require.Nil(t, err)

	entitlement := getEntitlementForTesting(resource, grantPrincipalType, roleEntitlement)
	r := &policyBuilder{
		resourceType: policyResourceType,
		client:       cliTest,
	}
	_, err = r.Grant(ctxTest, &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     grantPrincipal,
		},
	}, entitlement)
	require.Nil(t, err)
}

func parseEntitlementID(id string) (*v2.ResourceId, []string, error) {
	parts := strings.Split(id, ":")
	// Need to be at least 3 parts type:entitlement_id:slug
	if len(parts) < 3 || len(parts) > 3 {
		return nil, nil, fmt.Errorf("okta-connector: invalid resource id")
	}

	resourceId := &v2.ResourceId{
		ResourceType: parts[0],
		Resource:     strings.Join(parts[1:len(parts)-1], ":"),
	}

	return resourceId, parts, nil
}

func getEntitlementForTesting(resource *v2.Resource, resourceDisplayName, entitlement string) *v2.Entitlement {
	options := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s resource %s", resourceDisplayName, entitlement)),
		ent.WithDescription(fmt.Sprintf("%s of %s hcp", entitlement, resourceDisplayName)),
	}

	return ent.NewAssignmentEntitlement(resource, entitlement, options...)
}

func getPolicyForTesting(ctxTest context.Context, id string, name string) (*v2.Resource, error) {
	return policyResource(ctxTest, &client.APIResource{
		ID:   id,
		Name: name,
	}, nil)
}

func TestPolicyRevoke(t *testing.T) {
	if vaultToken == "" && vaultHost == "" {
		t.Skip()
	}

	revokeGrant := strings.Split("policy:root:assigned:user:adleyberry", ":")
	if len(revokeGrant) >= 1 && len(revokeGrant) <= 5 {
		policyId := revokeGrant[1]
		userId := revokeGrant[4]
		cliTest, err := getClientForTesting(ctxTest, client.DefaultAddress)
		require.Nil(t, err)

		resource, err := getPolicyForTesting(ctxTest, policyId, policyId)
		require.Nil(t, err)

		gr := grant.NewGrant(resource, assignedEntitlement, &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     userId,
		})
		r := &policyBuilder{
			resourceType: policyResourceType,
			client:       cliTest,
		}
		_, err = r.Revoke(ctxTest, gr)
		require.Nil(t, err)
	}
}
