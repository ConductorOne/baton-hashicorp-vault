package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestNewPassesVaultNamespaceToClient(t *testing.T) {
	var namespace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/auth" {
			namespace = r.Header.Get("X-Vault-Namespace")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	builder, _, err := New(context.Background(), &config.HashicorpVault{
		VaultHost:      srv.URL,
		VaultToken:     "t",
		VaultNamespace: "/admin/example/",
	}, nil)
	require.NoError(t, err)

	d := builder.(*Connector)
	_, _, err = d.client.ListAllAuthenticationMethods(context.Background())
	require.NoError(t, err)
	require.Equal(t, "admin/example", namespace)
}
