package client

import (
	"context"
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
