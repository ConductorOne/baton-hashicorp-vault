package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	SecEndpoint         = "v1/secret/metadata"
	AuthMethodsEndpoint = "v1/sys/auth"
	GroupsEndpoint      = "v1/identity/group/id"
	EntityEndpoint      = "v1/identity/entity/id"
	policiesEndpoint    = "v1/sys/policy"
	ApproleAuthEndpoint = "v1/sys/auth/approle"
	UserAuthEndpoint    = "v1/sys/auth/userpass"
	KvAuthEndpoint      = "v1/sys/mounts/kv"
	MethodList          = "LIST"
	approleType         = "approle"
	userpassType        = "userpass"
	kvType              = "kv"
	StatusBadRequest    = "400 Bad Request"
)

var listEndpoints = []string{KvEndpoint, SecEndpoint}

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

func (h *HCPClient) WithBearerToken(apiToken string) {
	h.auth.bearerToken = apiToken
}

func (h *HCPClient) WithAddress(host string) error {
	if !isValidUrl(host) {
		return fmt.Errorf("host is not valid")
	}

	h.baseUrl = host
	return nil
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
	isAuthError, err := hcpClient.CheckAuthenticationMethod(ctx, ApproleAuthEndpoint)
	if err != nil {
		if isAuthError && strings.Contains(err.Error(), StatusBadRequest) {
			err = hcpClient.EnableAuthMethod(ctx, ApproleAuthEndpoint, BodyEnableAuth{
				Type: approleType,
			})
			if err != nil {
				return err
			}
		}

		if !isAuthError {
			return err
		}
	}

	isAuthError, err = hcpClient.CheckAuthenticationMethod(ctx, UserAuthEndpoint)
	if err != nil {
		if isAuthError && strings.Contains(err.Error(), StatusBadRequest) {
			err = hcpClient.EnableAuthMethod(ctx, UserAuthEndpoint, BodyEnableAuth{
				Type: userpassType,
			})
			if err != nil {
				return err
			}
		}

		if !isAuthError {
			return err
		}
	}

	isAuthError, err = hcpClient.CheckAuthenticationMethod(ctx, KvAuthEndpoint)
	if err != nil {
		if isAuthError && strings.Contains(err.Error(), StatusBadRequest) {
			err = hcpClient.EnableAuthMethod(ctx, KvAuthEndpoint, BodySecret{
				Type: kvType,
			})
			if err != nil {
				return err
			}
		}

		if !isAuthError {
			return err
		}
	}

	return nil
}

func (h *HCPClient) CheckAuthenticationMethod(ctx context.Context, authMethod string) (bool, error) {
	authUrl, err := url.JoinPath(h.baseUrl, authMethod)
	if err != nil {
		return false, err
	}

	uri, err := url.Parse(authUrl)
	if err != nil {
		return false, err
	}

	var res any
	err = h.getAPIData(ctx,
		http.MethodGet,
		uri,
		&res,
	)
	if err != nil {
		return true, err
	}

	return false, nil
}

func (h *HCPClient) ListAllUsers(ctx context.Context) (*CommonAPIData, string, error) {
	users, err := h.GetUsers(ctx)
	if err != nil {
		return nil, "", err
	}

	return users, "", nil
}

func (h *HCPClient) ListAllSecrets(ctx context.Context, token string) (*CommonAPIData, string, error) {
	var (
		pageToken = 0
		err       error
	)
	if token != "" {
		pageToken, err = strconv.Atoi(token)
		if err != nil {
			return nil, "", err
		}
	}

	secrets, err := h.GetSecrets(ctx, listEndpoints[pageToken])
	if err != nil {
		return nil, "", err
	}

	if pageToken == (len(listEndpoints) - 1) {
		return secrets, "", nil
	}

	return secrets, strconv.Itoa(pageToken + 1), nil
}

// GetSecrets. List All Secrets.
// https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v1#ttls
func (h *HCPClient) GetSecrets(ctx context.Context, secretEndpoint string) (*CommonAPIData, error) {
	secretsUrl, err := url.JoinPath(h.baseUrl, secretEndpoint)
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

func (h *HCPClient) ListAllRoles(ctx context.Context) (*CommonAPIData, string, error) {
	roles, err := h.GetRoles(ctx)
	if err != nil {
		return nil, "", err
	}

	return roles, "", nil
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

func (h *HCPClient) ListAllPolicies(ctx context.Context) (*PolicyAPIData, string, error) {
	policies, err := h.GetPolicies(ctx)
	if err != nil {
		return nil, "", err
	}

	return policies, "", nil
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
	if err := h.doRequest(ctx, method, uri.String(), &res, nil); err != nil {
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

func (h *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) error {
	var (
		resp *http.Response
		err  error
	)
	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return err
	}

	req, err := h.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		uhttp.WithHeader(AuthHeaderName, h.getToken()),
		uhttp.WithJSONBody(body),
	)
	if err != nil {
		return err
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
		}
	}

	if resp != nil && (resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusBadRequest) {
		cErr, err := getError(resp)
		if err != nil {
			return err
		}

		// There is no data ot It's already authorized
		if len(cErr.Errors) == 0 || strings.Contains(cErr.Errors[0], "path is already in use") {
			return nil
		}
	}

	if err != nil {
		return err
	}

	return nil
}

// EnableAuthMethod. Enables you to use an auth method.
// https://developer.hashicorp.com/vault/docs/auth
// https://developer.hashicorp.com/vault/docs/auth/approle#via-the-api-1
func (h *HCPClient) EnableAuthMethod(ctx context.Context, apiUrl string, body any) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, apiUrl)
	if err != nil {
		return err
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, body); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) AddUsers(ctx context.Context, name, pwd string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return err
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyUsers{
		Password:        pwd,
		TokenPolicies:   []string{"admin", "default"},
		TokenBoundCidrs: []string{"127.0.0.1/32", "128.252.0.0/16"},
	}); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) AddRoles(ctx context.Context, name string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, RolesEndpoint, name)
	if err != nil {
		return err
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyRoles{
		TokenType:     "batch",
		TokenTTL:      "60m",
		TokenMaxTTL:   "180m",
		TokenPolicies: []string{"default"},
		Period:        0,
		BindSecretID:  true,
	}); err != nil {
		return err
	}

	return nil
}

func (h *HCPClient) AddSecrets(ctx context.Context, name, value string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, KvEndpoint, name)
	if err != nil {
		return err
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodySecrets{
		MyValue: value,
	}); err != nil {
		return err
	}

	return nil
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

func (h *HCPClient) ListAllAuthenticationMethods(ctx context.Context) (*authMethodsAPIData, string, error) {
	authUrl, err := url.JoinPath(h.baseUrl, AuthMethodsEndpoint)
	if err != nil {
		return nil, "", err
	}

	uri, err := url.Parse(authUrl)
	if err != nil {
		return nil, "", err
	}

	var res *authMethodsAPIData
	err = h.getAPIData(ctx,
		http.MethodGet,
		uri,
		&res,
	)
	if err != nil {
		return nil, "", err
	}

	return res, "", nil
}

func (h *HCPClient) ListAllGroups(ctx context.Context) (*groupsAPIData, string, error) {
	groupUrl, err := url.JoinPath(h.baseUrl, GroupsEndpoint)
	if err != nil {
		return nil, "", err
	}

	uri, err := url.Parse(groupUrl)
	if err != nil {
		return nil, "", err
	}

	var res *groupsAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, "", err
	}

	return res, "", nil
}

func (h *HCPClient) ListAllEntities(ctx context.Context) (*entityAPIData, string, error) {
	entityUrl, err := url.JoinPath(h.baseUrl, EntityEndpoint)
	if err != nil {
		return nil, "", err
	}

	uri, err := url.Parse(entityUrl)
	if err != nil {
		return nil, "", err
	}

	var res *entityAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, "", err
	}

	return res, "", nil
}

// UpdateUserPolicy. Update policies for an existing user.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#update-policies-on-user
func (h *HCPClient) UpdateUserPolicy(ctx context.Context, policy []string, name string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return err
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyUpdateUserPolicy{
		TokenPolicies: policy,
	}); err != nil {
		return err
	}

	return nil
}
