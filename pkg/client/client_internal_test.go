package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDoRequestRejectsUnsupportedMethod(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	hcp := NewClient()
	hcp.WithBearerToken("test-token")
	require.NoError(t, hcp.WithAddress(srv.URL))
	cli, err := New(context.Background(), hcp)
	require.NoError(t, err)
	requests.Store(0)

	err = cli.doRequest(context.Background(), http.MethodDelete, srv.URL, nil, nil)
	require.EqualError(t, err, `baton-hashicorp-vault: unsupported HTTP method "DELETE"`)
	require.Zero(t, requests.Load())
}

func TestDoRequestClassifiesNotFoundBodies(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{"empty errors", `{"errors":[]}`, ErrNotFound},
		{"route error", `{"errors":["no handler for route 'auth/userpass/users'"]}`, ErrNoRoute},
		{"empty body", "", ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(test.body))
			}))
			defer srv.Close()
			hcp := NewClient()
			hcp.WithBearerToken("test-token")
			require.NoError(t, hcp.WithAddress(srv.URL))
			cli, err := New(context.Background(), hcp)
			require.NoError(t, err)
			err = cli.doRequest(context.Background(), MethodList, srv.URL, nil, nil)
			require.True(t, errors.Is(err, test.want))
			if errors.Is(test.want, ErrNoRoute) {
				require.Contains(t, err.Error(), "auth/userpass/users")
			}
		})
	}
}
