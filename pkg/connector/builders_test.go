package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	"github.com/conductorone/baton-hashicorp-vault/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

func newBuilderTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	builder, _, err := New(context.Background(), &config.HashicorpVault{VaultHost: srv.URL, VaultToken: "token"}, nil)
	require.NoError(t, err)
	return builder.(*Connector)
}

func jsonResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestPolicyBuilderListSkipsPermissionDenied(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, http.StatusForbidden, `{"errors":["denied"]}`)
	}))
	resources, page, err := newPolicyBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Empty(t, resources)
	require.Empty(t, page.NextPageToken)
}

func TestUserBuilderListSkipsNoRoute(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, http.StatusNotFound, `{"errors":["no handler for route 'auth/userpass/users'"]}`)
	}))
	resources, page, err := newUserBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Empty(t, resources)
	require.Empty(t, page.NextPageToken)
}

func TestPolicyBuilderGrantsSkipsMissingUser(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/userpass/users":
			jsonResponse(w, http.StatusOK, `{"data":{"keys":["a","b","c"]}}`)
		case "/v1/auth/userpass/users/b":
			jsonResponse(w, http.StatusNotFound, `{"errors":["not found"]}`)
		default:
			jsonResponse(w, http.StatusOK, `{"data":{"token_policies":["p"]}}`)
		}
	}))
	policy := &v2.Resource{Id: &v2.ResourceId{ResourceType: policyResourceType.Id, Resource: "p"}}
	grants, _, err := newPolicyBuilder(d.client).Grants(context.Background(), policy, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 2)
	require.Equal(t, "a", grants[0].Principal.Id.Resource)
	require.Equal(t, "c", grants[1].Principal.Id.Resource)
}

func TestPolicyBuilderGrantsCachesUnavailableUserpassListing(t *testing.T) {
	var requests atomic.Int32
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users", r.URL.Path)
		requests.Add(1)
		jsonResponse(w, http.StatusForbidden, `{"errors":["denied"]}`)
	}))
	builder := newPolicyBuilder(d.client)
	for _, policyName := range []string{"first", "second"} {
		policy := &v2.Resource{Id: &v2.ResourceId{ResourceType: policyResourceType.Id, Resource: policyName}}
		grants, _, err := builder.Grants(context.Background(), policy, rs.SyncOpAttrs{})
		require.NoError(t, err)
		require.Empty(t, grants)
	}
	require.EqualValues(t, 1, requests.Load())
}

func TestPolicyBuilderGrantsDoesNotCacheSuccessfulUserpassListing(t *testing.T) {
	var requests atomic.Int32
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/auth/userpass/users", r.URL.Path)
		requests.Add(1)
		jsonResponse(w, http.StatusOK, `{"data":{"keys":[]}}`)
	}))
	builder := newPolicyBuilder(d.client)
	for _, policyName := range []string{"first", "second"} {
		policy := &v2.Resource{Id: &v2.ResourceId{ResourceType: policyResourceType.Id, Resource: policyName}}
		grants, _, err := builder.Grants(context.Background(), policy, rs.SyncOpAttrs{})
		require.NoError(t, err)
		require.Empty(t, grants)
	}
	require.EqualValues(t, 2, requests.Load())
}

func TestPolicyBuilderGrantsHonorsCancelledContext(t *testing.T) {
	var requests atomic.Int32
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		jsonResponse(w, http.StatusOK, `{}`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	policy := &v2.Resource{Id: &v2.ResourceId{ResourceType: policyResourceType.Id, Resource: "p"}}
	_, _, err := newPolicyBuilder(d.client).Grants(ctx, policy, rs.SyncOpAttrs{})
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, requests.Load())
}

func TestGroupAndEntityBuildersUseKeysWhenKeyInfoAbsent(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/identity/group/id" {
			jsonResponse(w, http.StatusOK, `{"data":{"keys":["g1","g2"]}}`)
			return
		}
		jsonResponse(w, http.StatusOK, `{"data":{"keys":["e1","e2"]}}`)
	}))
	groups, _, err := newGroupBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Equal(t, []string{"g1", "g2"}, []string{groups[0].Id.Resource, groups[1].Id.Resource})
	entities, _, err := newEntityBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Equal(t, []string{"e1", "e2"}, []string{entities[0].Id.Resource, entities[1].Id.Resource})
}

func TestTrimTrailingSlashAndUserLogin(t *testing.T) {
	require.Equal(t, "aws/ec2", trimTrailingSlash("aws/ec2/"))
	require.NotEqual(t, trimTrailingSlash("team/a/"), trimTrailingSlash("teama/"))
	resource, err := userResource(context.Background(), &client.APIResource{ID: "id", Name: "alice"}, nil)
	require.NoError(t, err)
	trait, err := rs.GetUserTrait(resource)
	require.NoError(t, err)
	require.Equal(t, "alice", trait.Login)
}

func TestSecretBuilderListsOneMountPerPage(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/mounts":
			jsonResponse(w, http.StatusOK, `{"data":{"kv/":{"type":"kv","options":{"version":"1"}},"secret/":{"type":"kv","options":{"version":"2"}},"cubbyhole/":{"type":"cubbyhole"}}}`)
		case "/v1/kv/":
			require.Equal(t, client.MethodList, r.Method)
			jsonResponse(w, http.StatusOK, `{"data":{"keys":["a","dir/"]}}`)
		case "/v1/kv/dir/":
			jsonResponse(w, http.StatusOK, `{"data":{"keys":["b"]}}`)
		case "/v1/secret/metadata/":
			require.Equal(t, client.MethodList, r.Method)
			jsonResponse(w, http.StatusOK, `{"data":{"keys":["x"]}}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	builder := newSecretBuilder(d.client)
	resources, page, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Equal(t, []string{"kv/a", "kv/dir/b"}, []string{resources[0].Id.Resource, resources[1].Id.Resource})
	require.NotEmpty(t, page.NextPageToken)

	resources, page, err = builder.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: page.NextPageToken}})
	require.NoError(t, err)
	require.Equal(t, []string{"secret/x"}, []string{resources[0].Id.Resource})
	require.Empty(t, page.NextPageToken)
}

func TestSecretBuilderSkipsPermissionDenied(t *testing.T) {
	t.Run("mount list", func(t *testing.T) {
		d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/v1/sys/mounts", r.URL.Path)
			jsonResponse(w, http.StatusForbidden, `{"errors":["denied"]}`)
		}))
		resources, page, err := newSecretBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{})
		require.NoError(t, err)
		require.Empty(t, resources)
		require.Empty(t, page.NextPageToken)
	})
	t.Run("mount path advances", func(t *testing.T) {
		d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/sys/mounts":
				jsonResponse(w, http.StatusOK, `{"data":{"kv/":{"type":"kv","options":{"version":"1"}},"secret/":{"type":"kv","options":{"version":"2"}}}}`)
			case "/v1/kv/":
				jsonResponse(w, http.StatusOK, `{"data":{"keys":[]}}`)
			case "/v1/secret/metadata/":
				jsonResponse(w, http.StatusForbidden, `{"errors":["denied"]}`)
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
		}))
		builder := newSecretBuilder(d.client)
		_, page, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{})
		require.NoError(t, err)
		resources, page, err := builder.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: page.NextPageToken}})
		require.NoError(t, err)
		require.Empty(t, resources)
		require.Empty(t, page.NextPageToken)
	})
}

func TestSecretBuilderRejectsUnknownMountToken(t *testing.T) {
	d := newBuilderTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/sys/mounts", r.URL.Path)
		jsonResponse(w, http.StatusOK, `{"data":{"kv/":{"type":"kv"}}}`)
	}))
	bag := &pagination.Bag{}
	bag.Push(pagination.PageState{ResourceTypeID: secretResourceType.Id, Token: "missing/"})
	token, err := bag.Marshal()
	require.NoError(t, err)
	_, _, err = newSecretBuilder(d.client).List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
	require.EqualError(t, err, `baton-hashicorp-vault: unknown KV mount "missing/" in pagination token`)
}
