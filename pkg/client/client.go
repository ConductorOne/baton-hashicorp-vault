package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

const (
	AuthHeaderName      = "X-Vault-Token"
	DefaultAddress      = "http://127.0.0.1:8200"
	UsersEndpoint       = "v1/auth/userpass/users"
	RolesEndpoint       = "v1/auth/approle/role"
	KvEndpoint          = "v1/kv"
	policiesEndpoint    = "v1/sys/policy"
	ApproleAuthEndpoint = "v1/sys/auth/approle"
	UserAuthEndpoint    = "v1/sys/auth/userpass"
	KvAuthEndpoint      = "v1/sys/mounts/kv"
	MethodList          = "LIST"
)

type HCPClient struct {
	httpClient *uhttp.BaseHttpClient
	auth       *auth
	baseUrl    string
}

type CustomErr struct {
	Errors []string `json:"errors"`
}

func NewClient() *HCPClient {
	return &HCPClient{
		httpClient: &uhttp.BaseHttpClient{},
		baseUrl:    "",
		auth: &auth{
			bearerToken: "",
		},
	}
}

func (h *HCPClient) WithBearerToken(apiToken string) *HCPClient {
	h.auth.bearerToken = apiToken
	return h
}

func (h *HCPClient) WithAddress(host string) (*HCPClient, error) {
	if !isValidUrl(host) {
		return h, fmt.Errorf("host is not valid")
	}

	h.baseUrl = host
	return h, nil
}

func (h *HCPClient) getToken() string {
	return h.auth.bearerToken
}

func isValidUrl(baseUrl string) bool {
	u, err := url.Parse(baseUrl)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func New(ctx context.Context, hcpClient *HCPClient) (*HCPClient, error) {
	var (
		clientToken = hcpClient.getToken()
		baseUrl     = DefaultAddress
	)
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	cli, err := uhttp.NewBaseHttpClientWithContext(context.Background(), httpClient)
	if err != nil {
		return hcpClient, err
	}

	if hcpClient.baseUrl != "" {
		baseUrl = hcpClient.baseUrl
	}

	if !isValidUrl(baseUrl) {
		return nil, fmt.Errorf("the url : %s is not valid", baseUrl)
	}

	// bearerToken
	hcp := HCPClient{
		httpClient: cli,
		baseUrl:    baseUrl,
		auth: &auth{
			bearerToken: clientToken,
		},
	}

	err = enableStores(ctx, &hcp)
	if err != nil {
		return nil, err
	}

	return &hcp, nil
}

func enableStores(ctx context.Context, hcpClient *HCPClient) error {
	err := hcpClient.EnableAuthMethod(ctx, ApproleAuthEndpoint, BodyEnableAuth{
		Type: "approle",
	})
	if err != nil {
		return err
	}

	err = hcpClient.EnableAuthMethod(ctx, UserAuthEndpoint, BodyEnableAuth{
		Type: "userpass",
	})
	if err != nil {
		return err
	}

	err = hcpClient.EnableAuthMethod(ctx, KvAuthEndpoint, BodySecret{
		Type:        "kv",
		Description: "",
		Config: Config{
			Options:         nil,
			DefaultLeaseTTL: "0s",
			MaxLeaseTTL:     "0s",
			ForceNoCache:    false,
		},
		Local:                 false,
		SealWrap:              false,
		ExternalEntropyAccess: false,
		Options: Options{
			Version: "1",
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) ListAllUsers(ctx context.Context) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	users, err := h.GetUsers(ctx)
	if err != nil {
		return nil, "", err
	}

	return users, nextPageToken, nil
}

func (h *HCPClient) ListAllSecrets(ctx context.Context) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	secrets, err := h.GetSecrets(ctx)
	if err != nil {
		return nil, "", err
	}

	return secrets, nextPageToken, nil
}

// GetSecrets. List All Secrets.
// https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1#ttls
func (h *HCPClient) GetSecrets(ctx context.Context) (*CommonAPIData, error) {
	secretsUrl, err := url.JoinPath(h.baseUrl, KvEndpoint)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(secretsUrl)
	if err != nil {
		return nil, err
	}

	var res *CommonAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#list-users
func (h *HCPClient) GetUsers(ctx context.Context) (*CommonAPIData, error) {
	usersUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(usersUrl)
	if err != nil {
		return nil, err
	}

	var res *CommonAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (h *HCPClient) ListAllRoles(ctx context.Context, opts PageOptions) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	roles, err := h.GetRoles(ctx)
	if err != nil {
		return nil, "", err
	}

	return roles, nextPageToken, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/approle#list-roles
func (h *HCPClient) GetRoles(ctx context.Context) (*CommonAPIData, error) {
	rolesUrl, err := url.JoinPath(h.baseUrl, RolesEndpoint)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(rolesUrl)
	if err != nil {
		return nil, err
	}

	var res *CommonAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (h *HCPClient) ListAllPolicies(ctx context.Context, opts PageOptions) (*PolicyAPIData, string, error) {
	var nextPageToken string = ""
	policies, err := h.GetPolicies(ctx)
	if err != nil {
		return nil, "", err
	}

	return policies, nextPageToken, nil
}

// GetPolicies. List All Policies.
// https://developer.hashicorp.com/vault/api-docs/system/policy
func (h *HCPClient) GetPolicies(ctx context.Context) (*PolicyAPIData, error) {
	policiesUrl, err := url.JoinPath(h.baseUrl, policiesEndpoint)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(policiesUrl)
	if err != nil {
		return nil, err
	}

	var res *PolicyAPIData
	err = h.getAPIData(ctx,
		http.MethodGet,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (h *HCPClient) getAPIData(ctx context.Context,
	method string,
	uri *url.URL,
	res any,
) error {
	if _, err := h.doRequest(ctx, method, uri.String(), &res, nil); err != nil {
		return err
	}

	return nil
}

func getError(resp *http.Response) (CustomErr, error) {
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return CustomErr{}, err
	}

	var cErr CustomErr
	err = json.Unmarshal(bytes, &cErr)
	if err != nil {
		return cErr, err
	}

	return cErr, nil
}

func (h *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) (any, error) {
	var (
		resp *http.Response
		err  error
	)
	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return nil, err
	}

	req, err := h.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		uhttp.WithHeader(AuthHeaderName, h.getToken()),
		uhttp.WithJSONBody(body),
	)
	if err != nil {
		return nil, err
	}

	switch method {
	case MethodList, http.MethodGet:
		resp, err = h.httpClient.Do(req, uhttp.WithResponse(&res))
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				cErr, err := getError(resp)
				if err != nil {
					return nil, err
				}

				// There is no data
				if len(cErr.Errors) == 0 {
					return nil, nil
				}
			}
		}
	case http.MethodPost:
		resp, err = h.httpClient.Do(req)
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusBadRequest {
				cErr, err := getError(resp)
				if err != nil {
					return nil, err
				}

				// It's already authorized
				if strings.Contains(cErr.Errors[0], "path is already in use") {
					return nil, nil
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return resp.StatusCode, nil
}

// EnableAuthMethod. The approle auth method allows machines or apps to authenticate with Vault-defined roles.
// An "AppRole" represents a set of Vault policies and login constraints that must be met to receive a token with those policies.
// https://developer.hashicorp.com/vault/docs/auth/approle
func (h *HCPClient) EnableAuthMethod(ctx context.Context, apiUrl string, body any) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, apiUrl)
	if err != nil {
		return err
	}

	var res any
	if _, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) AddUsers(ctx context.Context, name string) (any, error) {
	var statusCode any
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return nil, err
	}

	var res any
	if statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyUsers{
		Password:        "superSecretPassword",
		TokenPolicies:   []string{"admin", "default"},
		TokenBoundCidrs: []string{"127.0.0.1/32", "128.252.0.0/16"},
	}); err != nil {
		return nil, err
	}

	return statusCode, nil
}

func (h *HCPClient) AddRoles(ctx context.Context, name string) (any, error) {
	var statusCode any
	endpointUrl, err := url.JoinPath(h.baseUrl, RolesEndpoint, name)
	if err != nil {
		return nil, err
	}

	var res any
	if statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyRoles{
		TokenType:     "batch",
		TokenTTL:      "60m",
		TokenMaxTTL:   "180m",
		TokenPolicies: []string{"default"},
		Period:        0,
		BindSecretID:  true,
	}); err != nil {
		return nil, err
	}

	return statusCode, nil
}

func (h *HCPClient) GetUser(ctx context.Context, name string) (*UserAPIData, error) {
	userUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(userUrl)
	if err != nil {
		return nil, err
	}

	var res *UserAPIData
	err = h.getAPIData(ctx,
		http.MethodGet,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (h *HCPClient) UpdateUserPolicy(ctx context.Context, policy []string, name string) (any, error) {
	var statusCode any
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name, "policies")
	if err != nil {
		return nil, err
	}

	var res any
	if statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyUpdateUserPolicy{
		TokenPolicies: policy,
	}); err != nil {
		return nil, err
	}

	return statusCode, nil
}
