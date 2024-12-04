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
	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName      = "X-Vault-Token"
	DefaultAddress      = "http://127.0.0.1:8200"
	UsersEndpoint       = "v1/auth/userpass/users"
	RolesEndpoint       = "v1/auth/approle/role"
	policiesEndpoint    = "v1/sys/policy"
	ApproleAuthEndpoint = "v1/sys/auth/approle"
	UserAuthEndpoint    = "v1/sys/auth/userpass"
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

	return &hcp, nil
}

func (h *HCPClient) ListAllUsers(ctx context.Context) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	users, err := h.GetUsers(ctx)
	if err != nil {
		return nil, "", err
	}

	return users, nextPageToken, nil
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
	if _, _, err := h.doRequest(ctx, method, uri.String(), &res, nil); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) (http.Header, any, error) {
	var (
		resp *http.Response
		err  error
	)
	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return nil, nil, err
	}

	req, err := h.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		uhttp.WithHeader(AuthHeaderName, h.getToken()),
		uhttp.WithJSONBody(body),
	)
	if err != nil {
		return nil, nil, err
	}

	switch method {
	case MethodList, http.MethodGet:
		resp, err = h.httpClient.Do(req, uhttp.WithResponse(&res))
		if resp != nil {
			defer resp.Body.Close()
		}
	case http.MethodPost:
		resp, err = h.httpClient.Do(req)
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusBadRequest {
				bytes, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, nil, err
				}

				var cErr CustomErr
				err = json.Unmarshal(bytes, &cErr)
				if err != nil {
					return nil, nil, err
				}
				// It is already authorized
				if strings.Contains(cErr.Errors[0], "path is already in use") {
					return nil, nil, nil
				}
			}
		}
	}

	if err != nil {
		return nil, nil, err
	}

	return resp.Header, resp.StatusCode, nil
}

// EnableAuthMethod. The approle auth method allows machines or apps to authenticate with Vault-defined roles.
// An "AppRole" represents a set of Vault policies and login constraints that must be met to receive a token with those policies.
// https://developer.hashicorp.com/vault/docs/auth/approle
func (h *HCPClient) EnableAuthMethod(ctx context.Context, authMethod, apiUrl string) error {
	var (
		body struct {
			Type string `json:"type"`
		}
	)

	auth, err := json.Marshal(authMethod)
	if err != nil {
		return err
	}

	payload := []byte(fmt.Sprintf(`{ "type": %s }`, auth))
	err = json.Unmarshal(payload, &body)
	if err != nil {
		return err
	}

	endpointUrl, err := url.JoinPath(h.baseUrl, apiUrl)
	if err != nil {
		return err
	}

	var res any
	if _, _, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) AddUsers(ctx context.Context, name string) (any, error) {
	var (
		body struct {
			Password        string   `json:"password"`
			TokenPolicies   []string `json:"token_policies"`
			TokenBoundCidrs []string `json:"token_bound_cidrs"`
		}
		statusCode any
	)

	payload := []byte(`{ 
		"password": "superSecretPassword", 
		"token_policies": ["admin", "default"], 
		"token_bound_cidrs": ["127.0.0.1/32", "128.252.0.0/16"] 
	}`)
	err := json.Unmarshal(payload, &body)
	if err != nil {
		return nil, err
	}

	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return nil, err
	}

	var res any
	if _, statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
		return nil, err
	}

	return statusCode, nil
}

func (h *HCPClient) AddRoles(ctx context.Context, name string) (any, error) {
	var (
		body struct {
			TokenType     string   `json:"token_type"`
			TokenTTL      string   `json:"token_ttl"`
			TokenMaxTTL   string   `json:"token_max_ttl"`
			TokenPolicies []string `json:"token_policies"`
			Period        int      `json:"period"`
			BindSecretID  bool     `json:"bind_secret_id"`
		}
		statusCode any
	)

	payload := []byte(`{
		  "token_type": "batch",
		  "token_ttl": "60m",
		  "token_max_ttl": "180m",
		  "token_policies": ["default"],
		  "period": 0,
		  "bind_secret_id": true
		}`)
	err := json.Unmarshal(payload, &body)
	if err != nil {
		return nil, err
	}

	endpointUrl, err := url.JoinPath(h.baseUrl, RolesEndpoint, name)
	if err != nil {
		return nil, err
	}

	var res any
	if _, statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
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
	var (
		body struct {
			TokenPolicies []string `json:"token_policies"`
		}
		statusCode any
	)

	policies, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}

	payload := []byte(fmt.Sprintf(`{ "token_policies": %s }`, policies))
	err = json.Unmarshal(payload, &body)
	if err != nil {
		return nil, err
	}

	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name, "policies")
	if err != nil {
		return nil, err
	}

	var res any
	if _, statusCode, err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
		return nil, err
	}

	return statusCode, nil
}
