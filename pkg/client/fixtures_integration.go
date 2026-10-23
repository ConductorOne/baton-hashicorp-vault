//go:build integration

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type bodyUsers struct {
	Password      string   `json:"password"`
	TokenPolicies []string `json:"token_policies"`
}

type bodyRoles struct {
	TokenType     string   `json:"token_type"`
	TokenTTL      string   `json:"token_ttl"`
	TokenMaxTTL   string   `json:"token_max_ttl"`
	TokenPolicies []string `json:"token_policies"`
	Period        int      `json:"period"`
	BindSecretID  bool     `json:"bind_secret_id"`
}

type bodySecrets struct {
	MyValue string `json:"my-value"`
}

const kvFixtureEndpoint = "v1/kv"

func (h *HCPClient) AddUsers(ctx context.Context, name, pwd string, policies []string) error {
	endpointURL, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add user %q: %w", name, err)
	}

	return h.doRequest(ctx, http.MethodPost, endpointURL, nil, bodyUsers{Password: pwd, TokenPolicies: policies})
}

func (h *HCPClient) AddRoles(ctx context.Context, name string) error {
	endpointURL, err := url.JoinPath(h.baseUrl, RolesEndpoint, name)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add role %q: %w", name, err)
	}

	return h.doRequest(ctx, http.MethodPost, endpointURL, nil, bodyRoles{
		TokenType:     "batch",
		TokenTTL:      "60m",
		TokenMaxTTL:   "180m",
		TokenPolicies: []string{"default"},
		Period:        0,
		BindSecretID:  true,
	})
}

func (h *HCPClient) AddSecrets(ctx context.Context, name, value string) error {
	endpointURL, err := url.JoinPath(h.baseUrl, kvFixtureEndpoint, name)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add secret %q: %w", name, err)
	}

	return h.doRequest(ctx, http.MethodPost, endpointURL, nil, bodySecrets{MyValue: value})
}
