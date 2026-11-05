package client_test

import (
	"context"
	"encoding/json"
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

func clientJSONResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestNewDoesNotProbeMounts(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hcp := client.NewClient()
	hcp.WithBearerToken("test-token")
	require.NoError(t, hcp.WithAddress(srv.URL))
	_, err := client.New(context.Background(), hcp)
	require.NoError(t, err)
	require.Zero(t, requests.Load())
}

func TestNewAppRoleOnlyLogsIn(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/auth/approle/login", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth":{"client_token":"test-token"}}`))
	}))
	defer srv.Close()

	hcp := client.NewClient()
	hcp.WithAppRole("role-id", "secret-id")
	require.NoError(t, hcp.WithAddress(srv.URL))
	_, err := client.New(context.Background(), hcp)
	require.NoError(t, err)
	require.Equal(t, int32(1), requests.Load())
}

func TestBadRequestsReturnErrors(t *testing.T) {
	for _, body := range []string{"{}", `{"errors":[]}`, "null"} {
		t.Run("policies_"+body, func(t *testing.T) {
			cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(body))
			}))
			_, err := cli.GetPolicies(context.Background())
			require.Error(t, err)
		})
	}

	cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}))
	_, err := cli.GetUsers(context.Background())
	require.Error(t, err)
}

func TestNullResponsesReturnErrors(t *testing.T) {
	tests := []struct {
		name string
		call func(*client.HCPClient) error
	}{
		{"policies", func(c *client.HCPClient) error { _, err := c.GetPolicies(context.Background()); return err }},
		{"users", func(c *client.HCPClient) error { _, err := c.GetUsers(context.Background()); return err }},
		{"roles", func(c *client.HCPClient) error { _, err := c.GetRoles(context.Background()); return err }},
		{"groups", func(c *client.HCPClient) error { _, _, err := c.ListAllGroups(context.Background()); return err }},
		{"entities", func(c *client.HCPClient) error { _, _, err := c.ListAllEntities(context.Background()); return err }},
		{"auth_methods", func(c *client.HCPClient) error {
			_, _, err := c.ListAllAuthenticationMethods(context.Background())
			return err
		}},
		{"user", func(c *client.HCPClient) error { _, err := c.GetUser(context.Background(), "alice"); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("null"))
			}))
			endpoints := map[string]string{
				"policies":     "v1/sys/policies/acl",
				"users":        "v1/auth/userpass/users",
				"roles":        "v1/auth/approle/role",
				"groups":       "v1/identity/group/id",
				"entities":     "v1/identity/entity/id",
				"auth_methods": "v1/sys/auth",
				"user":         "v1/auth/userpass/users/alice",
			}
			require.EqualError(t, test.call(cli), "baton-hashicorp-vault: empty response from "+endpoints[test.name])
		})
	}
}

// LIST endpoints: Vault returns 404 when the engine is mounted but empty.
// The client must convert that into an empty result, not an error.

func TestListKVMounts(t *testing.T) {
	for name, response := range map[string]string{
		"data wrapped": `{"data":{"secret/":{"type":"kv","options":{"version":"1"}},` +
			`"kv/":{"type":"kv","options":{"version":"2"}},"generic/":{"type":"generic","options":null},` +
			`"other/":{"type":"pki"},"absent/":{"type":"kv"}}}`,
		"legacy top level": `{"secret/":{"type":"kv","options":{"version":"1"}},` +
			`"kv/":{"type":"kv","options":{"version":"2"}},"generic/":{"type":"generic","options":null},` +
			`"other/":{"type":"pki"},"absent/":{"type":"kv"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/v1/sys/mounts", r.URL.Path)
				clientJSONResponse(w, http.StatusOK, response)
			}))
			mounts, err := cli.ListKVMounts(context.Background())
			require.NoError(t, err)
			require.Equal(t, []client.KVMount{{Path: "absent/", Version: 1}, {Path: "generic/", Version: 1}, {Path: "kv/", Version: 2}, {Path: "secret/", Version: 1}}, mounts)
		})
	}
}

func TestListSecretPaths(t *testing.T) {
	t.Run("v1 recurses and ignores empty folders", func(t *testing.T) {
		var requests []string
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, client.MethodList, r.Method)
			requests = append(requests, r.URL.Path)
			switch r.URL.Path {
			case "/v1/kv/":
				clientJSONResponse(w, http.StatusOK, `{"data":{"keys":["a","dir/"]}}`)
			case "/v1/kv/dir/":
				clientJSONResponse(w, http.StatusOK, `{"data":{"keys":["b","empty/"]}}`)
			case "/v1/kv/dir/empty/":
				clientJSONResponse(w, http.StatusNotFound, `{"errors":[]}`)
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
		}))
		paths, err := cli.ListSecretPaths(context.Background(), client.KVMount{Path: "kv/", Version: 1}, 10)
		require.NoError(t, err)
		require.Equal(t, []string{"a", "dir/b"}, paths)
		require.Equal(t, []string{"/v1/kv/", "/v1/kv/dir/", "/v1/kv/dir/empty/"}, requests)
	})

	t.Run("v2 uses metadata only", func(t *testing.T) {
		var requests []string
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, client.MethodList, r.Method)
			require.NotContains(t, r.URL.Path, "/data/")
			requests = append(requests, r.URL.Path)
			switch r.URL.Path {
			case "/v1/secret/metadata/":
				clientJSONResponse(w, http.StatusOK, `{"data":{"keys":["dir/"]}}`)
			case "/v1/secret/metadata/dir/":
				clientJSONResponse(w, http.StatusOK, `{"data":{"keys":["b"]}}`)
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
		}))
		paths, err := cli.ListSecretPaths(context.Background(), client.KVMount{Path: "secret/", Version: 2}, 10)
		require.NoError(t, err)
		require.Equal(t, []string{"dir/b"}, paths)
		require.Equal(t, []string{"/v1/secret/metadata/", "/v1/secret/metadata/dir/"}, requests)
	})
}

func TestListSecretPathsDepthCap(t *testing.T) {
	requests := 0
	cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, client.MethodList, r.Method)
		requests++
		clientJSONResponse(w, http.StatusOK, `{"data":{"keys":["loop/"]}}`)
	}))
	const maxDepth = 3
	paths, err := cli.ListSecretPaths(context.Background(), client.KVMount{Path: "kv/", Version: 1}, maxDepth)
	require.NoError(t, err)
	require.Empty(t, paths)
	require.LessOrEqual(t, requests, maxDepth+1)
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
		case "/v1/sys/policies/acl":
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

	for _, key := range []string{"LIST /v1/auth/userpass/users", "LIST /v1/sys/policies/acl"} {
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
		if r.URL.Path == "/v1/sys/policies/acl" {
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

func TestGetUsersNoRouteReturnsError(t *testing.T) {
	cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":["no handler for route 'auth/userpass/users'"]}`))
	}))
	result, err := cli.GetUsers(context.Background())
	require.Nil(t, result)
	require.ErrorIs(t, err, client.ErrNoRoute)
	require.Contains(t, err.Error(), "auth/userpass/users")
}

func TestGetPoliciesModernAndLegacyFallback(t *testing.T) {
	t.Run("modern", func(t *testing.T) {
		legacyRequested := false
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/v1/sys/policies/acl", r.URL.Path)
			legacyRequested = legacyRequested || r.URL.Path == "/v1/sys/policy"
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":["a","b"]}`))
		}))
		policies, err := cli.GetPolicies(context.Background())
		require.NoError(t, err)
		require.Equal(t, []string{"a", "b"}, policies.Names())
		require.False(t, legacyRequested)
	})
	t.Run("legacy fallback", func(t *testing.T) {
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/sys/policies/acl" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["denied"]}`))
				return
			}
			require.Equal(t, "/v1/sys/policy", r.URL.Path)
			_, _ = w.Write([]byte(`{"policies":["x"]}`))
		}))
		policies, err := cli.GetPolicies(context.Background())
		require.NoError(t, err)
		require.Equal(t, []string{"x"}, policies.Names())
	})
	t.Run("both denied", func(t *testing.T) {
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["denied"]}`))
		}))
		_, err := cli.GetPolicies(context.Background())
		require.True(t, client.IsPermissionDenied(err))
	})
}

func TestLookupSelf(t *testing.T) {
	t.Run("decodes token information", func(t *testing.T) {
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"display_name":"baton","policies":["default","reader"],"ttl":3599,"renewable":true,"namespace_path":"admin/example/"}}`))
		}))
		info, err := cli.LookupSelf(context.Background())
		require.NoError(t, err)
		require.Equal(t, "baton", info.DisplayName)
		require.Equal(t, []string{"default", "reader"}, info.Policies)
		require.Equal(t, "admin/example/", info.NamespacePath)
	})

	t.Run("permission denied", func(t *testing.T) {
		cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := cli.LookupSelf(context.Background())
		require.True(t, client.IsPermissionDenied(err))
	})
}

func TestCapabilitiesSelf(t *testing.T) {
	for _, response := range []string{
		`{"sys/policy":["read"],"identity/entity/id":["deny"],"capabilities":["read"]}`,
		`{"data":{"sys/policy":["read"],"identity/entity/id":["deny"],"capabilities":["read"]}}`,
	} {
		t.Run(response[:7], func(t *testing.T) {
			var request struct {
				Paths []string `json:"paths"`
			}
			cli := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, "/v1/sys/capabilities-self", r.URL.Path)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}))
			paths := []string{"sys/policy", "identity/entity/id", "missing"}
			capabilities, err := cli.CapabilitiesSelf(context.Background(), paths)
			require.NoError(t, err)
			require.Equal(t, paths, request.Paths)
			require.Equal(t, map[string][]string{
				"sys/policy":         {"read"},
				"identity/entity/id": {"deny"},
				"missing":            {"deny"},
			}, capabilities)
		})
	}
}

// Vault answers the userpass update POST with 204 and no body; the client must
// not try to decode a response it did not ask for.
func TestUpdateUserPolicyAccepts204NoContent(t *testing.T) {
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	hcpClient := client.NewClient()
	hcpClient.WithBearerToken("test-token")
	require.NoError(t, hcpClient.WithAddress(srv.URL))
	cli, err := client.New(context.Background(), hcpClient)
	require.NoError(t, err)

	require.NoError(t, cli.UpdateUserPolicy(context.Background(), []string{"default"}, "alice"))
	require.Equal(t, http.MethodPost, method)
}
