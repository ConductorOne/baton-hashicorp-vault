package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/stretchr/testify/require"
)

// notFoundHandler simulates a Vault instance where every path returns 404.
var notFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
})

// newTestClient creates a real HCPClient pointed at the given test server.
// A bearer token is pre-set so New() skips AppRole login.
func newTestClient(t *testing.T, handler http.Handler) *client.HCPClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("test-token")
	err := hcpClient.WithAddress(srv.URL)
	require.NoError(t, err)

	cli, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)
	return cli
}

// LIST endpoints: Vault returns 404 when the engine is mounted but empty.
// The client must convert that into an empty result, not an error.

func TestGetSecrets_404_ReturnsEmpty(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, err := cli.GetSecrets(context.Background(), client.KvEndpoint)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Data.Keys)
}

func TestGetUsers_404_ReturnsEmpty(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, err := cli.GetUsers(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Data.Keys)
}

func TestGetRoles_404_ReturnsEmpty(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, err := cli.GetRoles(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Data.Keys)
}

func TestListAllGroups_404_ReturnsEmpty(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, _, err := cli.ListAllGroups(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestListAllEntities_404_ReturnsEmpty(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, _, err := cli.ListAllEntities(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
}

// System/single-resource endpoints: 404 means the resource genuinely does not
// exist and must be returned as an error, not silently converted to an empty result.

func TestGetUser_404_ReturnsError(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, err := cli.GetUser(context.Background(), "nonexistent")
	require.Error(t, err)
	require.True(t, errors.Is(err, client.ErrNotFound))
	require.Nil(t, result)
}

func TestGetPolicies_404_ReturnsError(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, _, err := cli.ListAllPolicies(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, client.ErrNotFound))
	require.Nil(t, result)
}

func TestListAllAuthenticationMethods_404_ReturnsError(t *testing.T) {
	cli := newTestClient(t, notFoundHandler)
	result, _, err := cli.ListAllAuthenticationMethods(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, client.ErrNotFound))
	require.Nil(t, result)
}
