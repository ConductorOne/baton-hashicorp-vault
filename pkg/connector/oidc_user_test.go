package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

const entityListJSON = `{"data":{"keys":["e-oidc","e-jwt","e-userpass","e-nometa"],"key_info":{
 "e-oidc":{"name":"entity_a","aliases":[{"name":"sub-123","mount_type":"oidc","mount_path":"auth/oidc/"}]},
 "e-jwt":{"name":"entity_b","disabled":true,"aliases":[{"name":"bob@example.com","mount_type":"jwt","mount_path":"auth/jwt/"}]},
 "e-userpass":{"name":"entity_c","aliases":[{"name":"carol","mount_type":"userpass"}]},
 "e-nometa":{"name":"entity_d","aliases":[{"name":"sub-999","mount_type":"oidc","mount_path":"auth/oidc/"}]}}}}`

var entityReads = map[string]string{
	"e-oidc":   `{"data":{"name":"entity_a","aliases":[{"name":"sub-123","mount_type":"oidc","mount_path":"auth/oidc/","metadata":{"email":"alice@example.com"}}]}}`,
	"e-jwt":    `{"data":{"name":"entity_b","disabled":true,"aliases":[{"name":"bob@example.com","mount_type":"jwt","mount_path":"auth/jwt/"}]}}`,
	"e-nometa": `{"data":{"name":"entity_d","aliases":[{"name":"sub-999","mount_type":"oidc","mount_path":"auth/oidc/"}]}}`,
}

func newVaultStub(t *testing.T) *client.HCPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/identity/entity/id":
			fmt.Fprint(w, entityListJSON)
		case strings.HasPrefix(r.URL.Path, "/v1/identity/entity/id/"):
			body, ok := entityReads[strings.TrimPrefix(r.URL.Path, "/v1/identity/entity/id/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprint(w, body)
		case r.URL.Path == "/v1/auth/userpass/users":
			fmt.Fprint(w, `{"data":{"keys":["dave"]}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := client.NewClient()
	c.WithBearerToken("t")
	require.NoError(t, c.WithAddress(srv.URL))
	cli, err := client.New(context.Background(), c)
	require.NoError(t, err)
	return cli
}

func TestUserList_IncludesOIDCUsersWithEmail(t *testing.T) {
	ctx := context.Background()
	ub := newUserBuilder(newVaultStub(t))

	var all []*v2.Resource
	token := ""
	for i := 0; i < 5; i++ {
		rs, res, err := ub.List(ctx, nil, rsTypes.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		all = append(all, rs...)
		token = res.NextPageToken
		if token == "" {
			break
		}
	}
	require.Empty(t, token)

	byID := map[string]*v2.Resource{}
	for _, r := range all {
		byID[r.Id.Resource] = r
	}
	require.Len(t, byID, 4) // dave + 3 OIDC/JWT entities; userpass-only entity excluded
	require.Contains(t, byID, "dave")
	require.NotContains(t, byID, "e-userpass")

	emailOf := func(id string) string {
		ut, err := rsTypes.GetUserTrait(byID[id])
		require.NoError(t, err)
		for _, e := range ut.Emails {
			if e.IsPrimary {
				return e.Address
			}
		}
		return ""
	}
	require.Equal(t, "alice@example.com", emailOf("e-oidc")) // alias metadata
	require.Equal(t, "bob@example.com", emailOf("e-jwt"))    // alias name is an email
	require.Equal(t, "", emailOf("e-nometa"))                // no email: still synced

	ut, err := rsTypes.GetUserTrait(byID["e-jwt"])
	require.NoError(t, err)
	require.Equal(t, v2.UserTrait_Status_STATUS_DISABLED, ut.Status.Status)
}

func TestOIDCEmail_Precedence(t *testing.T) {
	al := []client.EntityAlias{{
		Name:           "bob@example.com",
		Metadata:       map[string]string{"Email": "meta@example.com"},
		CustomMetadata: map[string]string{"email": "custom@example.com"},
	}}
	require.Equal(t, "meta@example.com", oidcEmail(&client.Entity{}, al))
	al[0].Metadata = nil
	require.Equal(t, "custom@example.com", oidcEmail(&client.Entity{}, al))
	al[0].CustomMetadata = nil
	require.Equal(t, "ent@example.com", oidcEmail(&client.Entity{Metadata: map[string]string{"email": "ent@example.com"}}, al))
	require.Equal(t, "bob@example.com", oidcEmail(&client.Entity{}, al))
	require.Equal(t, "", oidcEmail(&client.Entity{Metadata: map[string]string{"email": "not-an-email"}}, []client.EntityAlias{{Name: "sub-1"}}))
}

// stubWith builds a client against a handler for tests needing custom behavior.
func stubWith(t *testing.T, h http.HandlerFunc) *client.HCPClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := client.NewClient()
	c.WithBearerToken("t")
	require.NoError(t, c.WithAddress(srv.URL))
	cli, err := client.New(context.Background(), c)
	require.NoError(t, err)
	return cli
}

func listAll(t *testing.T, ub *userBuilder) []*v2.Resource {
	t.Helper()
	var all []*v2.Resource
	token := ""
	for i := 0; i < 50; i++ {
		rs, res, err := ub.List(context.Background(), nil, rsTypes.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		require.NoError(t, err)
		all = append(all, rs...)
		token = res.NextPageToken
		if token == "" {
			return all
		}
	}
	t.Fatal("pagination did not terminate")
	return nil
}

func TestUserList_PaginatesOIDCEntities(t *testing.T) {
	old := oidcPageSize
	oidcPageSize = 2
	t.Cleanup(func() { oidcPageSize = old })

	var keyInfo []string
	for i := 0; i < 5; i++ {
		keyInfo = append(keyInfo, fmt.Sprintf(`"e%d":{"name":"n%d","aliases":[{"name":"a%d","mount_type":"oidc"}]}`, i, i, i))
	}
	list := `{"data":{"key_info":{` + strings.Join(keyInfo, ",") + `}}}`
	cli := stubWith(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/identity/entity/id":
			fmt.Fprint(w, list)
		case strings.HasPrefix(r.URL.Path, "/v1/identity/entity/id/"):
			fmt.Fprint(w, `{"data":{"name":"n","aliases":[{"name":"a","mount_type":"oidc"}]}}`)
		case r.URL.Path == "/v1/auth/userpass/users":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	all := listAll(t, newUserBuilder(cli))
	require.Len(t, all, 5)
}

func TestUserList_SkipsEntityDeletedMidSync(t *testing.T) {
	cli := stubWith(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/identity/entity/id":
			fmt.Fprint(w, `{"data":{"key_info":{"gone":{"aliases":[{"name":"a","mount_type":"oidc"}]},"here":{"aliases":[{"name":"b","mount_type":"oidc"}]}}}}`)
		case r.URL.Path == "/v1/identity/entity/id/here":
			fmt.Fprint(w, `{"data":{"name":"here","aliases":[{"name":"b","mount_type":"oidc"}]}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	all := listAll(t, newUserBuilder(cli))
	require.Len(t, all, 1)
	require.Equal(t, "here", all[0].Id.Resource)
}

func TestUserList_ForbiddenEntitiesKeepsUserpassUsers(t *testing.T) {
	cli := stubWith(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/userpass/users":
			fmt.Fprint(w, `{"data":{"keys":["dave"]}}`)
		case strings.HasPrefix(r.URL.Path, "/v1/identity/"):
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"errors":["permission denied"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	all := listAll(t, newUserBuilder(cli))
	require.Len(t, all, 1)
	require.Equal(t, "dave", all[0].Id.Resource)
}
