package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/stretchr/testify/require"
)

// Validate() is called by the SDK at the start of every sync. Static-token
// auth never exercises the token before this (appRoleLogin is skipped, and
// the mount-bootstrap check treats 403 as "probably fine, just under-scoped"
// rather than a definitive answer) - Validate must be the thing that catches
// an invalid/expired --vault-token.

func TestValidate_ValidToken_ReturnsNoError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	cli, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)

	c := &Connector{client: cli}
	_, err = c.Validate(context.Background())
	require.NoError(t, err)
}

func TestValidate_InvalidToken_ReturnsError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("bad-token")
	hcpClient.WithSkipMountBootstrap(true)
	require.NoError(t, hcpClient.WithAddress(srv.URL))

	cli, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)

	c := &Connector{client: cli}
	_, err = c.Validate(context.Background())
	require.Error(t, err)
}
