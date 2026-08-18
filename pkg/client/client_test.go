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

// notFoundHandler simulates a Vault instance where every path returns 404,
// except the sys/auth and sys/mounts checks client.New() runs at startup to
// bootstrap the approle/userpass/kv mounts - those report the mount as
// already present (200) so tests can focus on the 404 behavior of the
// endpoint under test.
var notFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/" + client.ApproleAuthEndpoint, "/" + client.UserAuthEndpoint, "/" + client.KvAuthEndpoint:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
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

// Mount bootstrap: client.New() checks the approle/userpass/kv mounts and
// enables any that are missing. A token without sudo capability gets a 403
// on the check itself; that must fail loudly rather than be swallowed.

func TestNew_MountCheckForbidden_ReturnsError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+client.ApproleAuthEndpoint {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("test-token")
	require.NoError(t, hcpClient.WithAddress(srv.URL))

	_, err := client.New(context.Background(), hcpClient)
	require.Error(t, err)
}

func TestNew_MountAbsent_CreatesMount(t *testing.T) {
	var created bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/"+client.ApproleAuthEndpoint && !created:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["No auth engine at approle/"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/"+client.ApproleAuthEndpoint:
			created = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("test-token")
	require.NoError(t, hcpClient.WithAddress(srv.URL))

	_, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)
	require.True(t, created, "expected EnableAuthMethod to POST to the missing approle mount")
}

func TestNew_SkipMountBootstrap_SkipsChecks(t *testing.T) {
	var sysCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + client.ApproleAuthEndpoint, "/" + client.UserAuthEndpoint, "/" + client.KvAuthEndpoint:
			sysCalled = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("test-token")
	hcpClient.WithSkipMountBootstrap(true)
	require.NoError(t, hcpClient.WithAddress(srv.URL))

	_, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)
	require.False(t, sysCalled, "expected no mount-bootstrap requests when skip flag is set")
}
