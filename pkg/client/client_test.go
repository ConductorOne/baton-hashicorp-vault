package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestNamespaceHeaderOnAppRoleLoginAndRequests(t *testing.T) {
	var loginNamespace, listNamespace, getNamespace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			loginNamespace = r.Header.Get(client.NamespaceHeaderName)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth":{"client_token":"test-token"}}`))
		case "/v1/auth/userpass/users":
			listNamespace = r.Header.Get(client.NamespaceHeaderName)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"keys":[]}}`))
		case "/v1/sys/policy":
			getNamespace = r.Header.Get(client.NamespaceHeaderName)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"keys":[]}}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	hcp := client.NewClient()
	require.NoError(t, hcp.WithAddress(srv.URL))
	hcp.WithNamespace("/admin/example/")
	hcp.WithAppRole("role-id", "secret-id")
	cli, err := client.New(context.Background(), hcp)
	require.NoError(t, err)
	_, err = cli.GetUsers(context.Background())
	require.NoError(t, err)
	_, err = cli.GetPolicies(context.Background())
	require.NoError(t, err)

	require.Equal(t, "admin/example", loginNamespace)
	require.Equal(t, "admin/example", listNamespace)
	require.Equal(t, "admin/example", getNamespace)
}

func TestRequestHeadersAndBodies(t *testing.T) {
	type requestDetails struct {
		contentLength int64
		contentType   string
		accept        string
		body          string
		namespace     []string
	}
	details := map[string]requestDetails{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		details[r.Method+" "+r.URL.Path] = requestDetails{
			contentLength: r.ContentLength,
			contentType:   r.Header.Get("Content-Type"),
			accept:        r.Header.Get("Accept"),
			body:          string(body),
			namespace:     r.Header.Values(client.NamespaceHeaderName),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"keys":[]}}`))
	}))
	defer srv.Close()

	cli := newTestClient(t, srv.Config.Handler)
	_, err := cli.GetUsers(context.Background())
	require.NoError(t, err)
	_, err = cli.GetPolicies(context.Background())
	require.NoError(t, err)
	require.NoError(t, cli.UpdateUserPolicy(context.Background(), []string{"default"}, "alice"))

	for _, key := range []string{"LIST /v1/auth/userpass/users", "GET /v1/sys/policy"} {
		detail := details[key]
		require.Equal(t, int64(0), detail.contentLength, key)
		require.Empty(t, detail.contentType, key)
		require.Empty(t, detail.body, key)
		require.Equal(t, "application/json", detail.accept, key)
		require.Empty(t, detail.namespace, key)
	}
	post := details["POST /v1/auth/userpass/users/alice"]
	require.Equal(t, "application/json", post.contentType)
	require.NotEmpty(t, post.body)
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/v1/sys/policy" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	cli := newTestClient(t, srv.Config.Handler)
	_, err := cli.GetPolicies(context.Background())
	require.Error(t, err)
	require.Zero(t, redirected.Load())
}
