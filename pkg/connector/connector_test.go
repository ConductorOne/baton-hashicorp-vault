package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
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

func TestRoleIsSyncOnlyAndPolicyIsProvisionable(t *testing.T) {
	_, roleProvisioner := any(newRoleBuilder(nil)).(connectorbuilder.ResourceProvisionerV2)
	_, policyProvisioner := any(newPolicyBuilder(nil)).(connectorbuilder.ResourceProvisionerV2)
	require.False(t, roleProvisioner)
	require.True(t, policyProvisioner)
}

func TestNewRequiresCredentials(t *testing.T) {
	_, _, err := New(context.Background(), &config.HashicorpVault{}, nil)
	require.EqualError(t, err, "baton-hashicorp-vault: no Vault credentials configured: set --vault-token or --role-id and --secret-id")
}

func TestValidateInvalidCredentials(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
	}))
	_, err := d.Validate(context.Background())
	require.ErrorContains(t, err, "invalid Vault credentials")
}

func TestValidateMissingCapabilitiesOnlyWarns(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_, _ = w.Write([]byte(`{"data":{"display_name":"baton","policies":["default"]}}`))
		case "/v1/sys/capabilities-self":
			_, _ = w.Write([]byte(`{"sys/policies/acl":["deny"],"sys/policy":["deny"],"sys/auth":["read"],` +
				`"auth/userpass/users":["list"],"auth/approle/role":["list"],"identity/entity/id":["list"],` +
				`"identity/group/id":["list"],"sys/mounts":["read"]}`))
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	annotations, err := d.Validate(context.Background())
	require.NoError(t, err)
	require.Nil(t, annotations)
}

func TestValidateCapabilitiesSelfFailureOnlyWarns(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		require.Equal(t, "/v1/sys/capabilities-self", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
	}))
	annotations, err := d.Validate(context.Background())
	require.NoError(t, err)
	require.Nil(t, annotations)
}

func TestMissingCapabilitiesPolicyFallbackAndRoot(t *testing.T) {
	capabilities := make(map[string][]string, len(requiredCapabilities))
	for _, required := range requiredCapabilities {
		capabilities[required.path] = []string{"deny"}
	}
	capabilities["sys/policy"] = []string{"read"}
	missing := missingCapabilities(capabilities)
	require.NotContains(t, missing, "policy")

	capabilities["identity/entity/id"] = []string{"root"}
	missing = missingCapabilities(capabilities)
	require.NotContains(t, missing, "entity")
}
