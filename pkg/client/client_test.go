package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
// enables any that are missing. Checking (and creating) a mount requires
// sudo capability in Vault, so a least-privilege sync-only token always gets
// 401/403 here - that's customer config, not a connector bug, and must not
// block startup. A genuine server error must still fail loudly.

func TestNew_MountCheckPermissionDenied_WarnsAndContinues(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/" + client.ApproleAuthEndpoint, "/" + client.UserAuthEndpoint, "/" + client.KvAuthEndpoint:
					w.WriteHeader(status)
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
		})
	}
}

func TestNew_MountCheckServerError_ReturnsError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+client.ApproleAuthEndpoint {
			w.WriteHeader(http.StatusInternalServerError)
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
	statusCases := []struct {
		name         string
		absentStatus int
		absentBody   string
		contentType  string
	}{
		{
			name:         "400 reports mount not mounted",
			absentStatus: http.StatusBadRequest,
			absentBody:   `{"errors":["No auth engine at approle/"]}`,
			contentType:  "application/json",
		},
		{
			name:         "404 short-circuits to ErrNotFound",
			absentStatus: http.StatusNotFound,
		},
	}
	paths := []string{client.ApproleAuthEndpoint, client.UserAuthEndpoint, client.KvAuthEndpoint}

	for _, tt := range statusCases {
		for _, path := range paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				var created atomic.Bool
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/"+path && !created.Load():
						if tt.contentType != "" {
							w.Header().Set("Content-Type", tt.contentType)
						}
						w.WriteHeader(tt.absentStatus)
						if tt.absentBody != "" {
							_, _ = w.Write([]byte(tt.absentBody))
						}
					case r.Method == http.MethodPost && r.URL.Path == "/"+path:
						created.Store(true)
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
				require.True(t, created.Load(), "expected EnableAuthMethod to POST to the missing mount at %q", path)
			})
		}
	}
}

func TestNew_SkipMountBootstrap_SkipsChecks(t *testing.T) {
	var sysCalled atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + client.ApproleAuthEndpoint, "/" + client.UserAuthEndpoint, "/" + client.KvAuthEndpoint:
			sysCalled.Store(true)
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
	require.False(t, sysCalled.Load(), "expected no mount-bootstrap requests when skip flag is set")
}
