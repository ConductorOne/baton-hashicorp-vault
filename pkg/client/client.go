package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotFound is returned when Vault responds with a 404 whose errors array is
// absent or empty. For LIST operations this means the path is mounted but has
// no entries; callers that expect a collection should convert it to an empty
// result. A 404 with errors is ErrNoRoute instead.
var ErrNotFound = errors.New("baton-hashicorp-vault: resource not found")

// ErrNoRoute is returned when Vault reports that a requested path does not
// exist or is not permitted.
var ErrNoRoute = errors.New("baton-hashicorp-vault: path does not exist or is not permitted")

const (
	AuthHeaderName       = "X-Vault-Token"
	NamespaceHeaderName  = "X-Vault-Namespace"
	DefaultAddress       = "http://127.0.0.1:8200"
	UsersEndpoint        = "v1/auth/userpass/users"
	RolesEndpoint        = "v1/auth/approle/role"
	AuthMethodsEndpoint  = "v1/sys/auth"
	GroupsEndpoint       = "v1/identity/group/id"
	EntityEndpoint       = "v1/identity/entity/id"
	policiesEndpoint     = "v1/sys/policy"
	PoliciesACLEndpoint  = "v1/sys/policies/acl"
	AppRoleLoginEndpoint = "v1/auth/approle/login"
	LookupSelfEndpoint   = "v1/auth/token/lookup-self"
	CapabilitiesEndpoint = "v1/sys/capabilities-self"
	MethodList           = "LIST"
)

type HCPClient struct {
	httpClient *uhttp.BaseHttpClient
	auth       *auth
	baseUrl    string
	namespace  string
	mu         sync.Mutex
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

func (h *HCPClient) WithAppRole(roleID, secretID string) {
	h.auth.roleID = roleID
	h.auth.secretID = secretID
}

// WithNamespace sets the Vault Enterprise or HCP Vault namespace to send with requests.
func (h *HCPClient) WithNamespace(ns string) {
	h.namespace = strings.Trim(ns, "/")
}

func (h *HCPClient) IsConfigured() bool {
	return h.auth.bearerToken != "" || (h.auth.roleID != "" && h.auth.secretID != "")
}

func (h *HCPClient) appRoleLogin(ctx context.Context) error {
	loginURL, err := url.JoinPath(h.baseUrl, AppRoleLoginEndpoint)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build approle login URL: %w", err)
	}

	uri, err := url.Parse(loginURL)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to parse approle login URL: %w", err)
	}

	req, err := h.httpClient.NewRequest(ctx,
		http.MethodPost,
		uri,
		h.requestOptions("", appRoleLoginRequest{
			RoleID:   h.auth.roleID,
			SecretID: h.auth.secretID,
		})...,
	)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to create approle login request: %w", err)
	}

	var res appRoleLoginResponse
	resp, err := h.httpClient.Do(req, uhttp.WithResponse(&res))
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: approle login failed: %w", err)
	}

	if res.Auth.ClientToken == "" {
		return fmt.Errorf("baton-hashicorp-vault: approle login returned empty token")
	}

	h.auth.bearerToken = res.Auth.ClientToken
	if res.Auth.LeaseDuration > 0 {
		ttl := time.Duration(res.Auth.LeaseDuration) * time.Second
		buffer := 30 * time.Second
		if buffer >= ttl {
			buffer = ttl / 2
		}
		h.auth.expiresAt = time.Now().UTC().Add(ttl - buffer)
	}
	return nil
}

func (h *HCPClient) WithAddress(host string) error {
	if !isValidUrl(host) {
		return fmt.Errorf("baton-hashicorp-vault: host %q is not valid", host)
	}

	h.baseUrl = host
	return nil
}

func (h *HCPClient) getToken() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.auth.bearerToken
}

// Namespace returns the configured Vault namespace.
func (h *HCPClient) Namespace() string {
	return h.namespace
}

// ensureValidToken refreshes the AppRole token if it has expired or is about to.
// Static bearer token auth (no roleID/secretID) is unmanaged and returned as-is.
func (h *HCPClient) ensureValidToken(ctx context.Context) (string, error) {
	if h.auth.roleID == "" || h.auth.secretID == "" {
		return h.getToken(), nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// expiresAt zero means no TTL (e.g. root token) — treat as non-expiring.
	if h.auth.bearerToken != "" && (h.auth.expiresAt.IsZero() || time.Now().UTC().Before(h.auth.expiresAt)) {
		return h.auth.bearerToken, nil
	}

	if err := h.appRoleLogin(ctx); err != nil {
		return "", err
	}
	return h.auth.bearerToken, nil
}

func (h *HCPClient) requestOptions(token string, body any) []uhttp.RequestOption {
	options := make([]uhttp.RequestOption, 0, 4)
	if h.namespace != "" {
		options = append(options, uhttp.WithHeader(NamespaceHeaderName, h.namespace))
	}
	if token != "" {
		options = append(options, uhttp.WithHeader(AuthHeaderName, token))
	}
	options = append(options, uhttp.WithAcceptJSONHeader())
	if body != nil {
		options = append(options, uhttp.WithJSONBody(body))
	}
	return options
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
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to create HTTP client: %w", err)
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cli, err := uhttp.NewBaseHttpClientWithContext(ctx, httpClient,
		uhttp.WithCacheKeyHeaders(NamespaceHeaderName, AuthHeaderName),
	)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to initialize HTTP client: %w", err)
	}

	if hcpClient.baseUrl != "" {
		baseUrl = hcpClient.baseUrl
	}

	if !isValidUrl(baseUrl) {
		return nil, fmt.Errorf("baton-hashicorp-vault: vault address %q is not valid", baseUrl)
	}

	hcp := HCPClient{
		httpClient: cli,
		baseUrl:    baseUrl,
		namespace:  hcpClient.namespace,
		auth: &auth{
			bearerToken: clientToken,
			roleID:      hcpClient.auth.roleID,
			secretID:    hcpClient.auth.secretID,
		},
	}

	if hcp.auth.roleID != "" && hcp.auth.secretID != "" {
		if err := hcp.appRoleLogin(ctx); err != nil {
			return nil, err
		}
	}

	return &hcp, nil
}

func (h *HCPClient) ListAllUsers(ctx context.Context) (*CommonAPIData, string, error) {
	users, err := h.GetUsers(ctx)
	if err != nil {
		return nil, "", err
	}

	return users, "", nil
}

// ListKVMounts returns all mounted KV engines, including legacy generic mounts.
func (h *HCPClient) ListKVMounts(ctx context.Context) ([]KVMount, error) {
	if h == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: client is nil")
	}
	endpoint, err := url.JoinPath(h.baseUrl, "v1/sys/mounts")
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build mounts URL: %w", err)
	}
	var response map[string]json.RawMessage
	if err := h.doRequest(ctx, http.MethodGet, endpoint, &response, nil); err != nil {
		return nil, err
	}

	mountData := response
	if raw, ok := response["data"]; ok {
		var wrapped map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped != nil {
			mountData = wrapped
		}
	}

	mounts := make([]KVMount, 0)
	for path, raw := range mountData {
		var mount struct {
			Type    string `json:"type"`
			Options *struct {
				Version string `json:"version"`
			} `json:"options"`
		}
		if err := json.Unmarshal(raw, &mount); err != nil || (mount.Type != "kv" && mount.Type != "generic") {
			continue
		}
		version := 1
		if mount.Options != nil && mount.Options.Version == "2" {
			version = 2
		}
		mounts = append(mounts, KVMount{Path: path, Version: version})
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })
	return mounts, nil
}

// ListSecretPaths lists leaf secret paths relative to mount without reading secret data.
func (h *HCPClient) ListSecretPaths(ctx context.Context, mount KVMount, maxDepth int) ([]string, error) {
	if h == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: client is nil")
	}
	if maxDepth < 0 {
		maxDepth = 0
	}
	type pendingPath struct {
		path  string
		depth int
	}
	pending := []pendingPath{{}}
	leaves := make([]string, 0)
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		endpoint := "v1/" + mount.Path
		if mount.Version == 2 {
			endpoint += "metadata/"
		}
		endpoint += current.path
		endpointURL, err := url.JoinPath(h.baseUrl, endpoint)
		if err != nil {
			return nil, fmt.Errorf("baton-hashicorp-vault: failed to build secret list URL: %w", err)
		}
		var response CommonAPIData
		if err := h.doRequest(ctx, MethodList, endpointURL, &response, nil); err != nil {
			if IsNotFound(err) {
				continue
			}
			return nil, err
		}
		for _, key := range response.Data.Keys {
			path := current.path + key
			if strings.HasSuffix(key, "/") {
				if current.depth >= maxDepth {
					ctxzap.Extract(ctx).Warn("baton-hashicorp-vault: maximum secret path depth reached", zap.String("mount", mount.Path), zap.String("path", path), zap.Int("max_depth", maxDepth))
					continue
				}
				pending = append(pending, pendingPath{path: path, depth: current.depth + 1})
				continue
			}
			leaves = append(leaves, path)
		}
	}
	sort.Strings(leaves)
	return leaves, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#list-users
func (h *HCPClient) GetUsers(ctx context.Context) (*CommonAPIData, error) {
	usersUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build users URL: %w", err)
	}

	uri, err := url.Parse(usersUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse users URL: %w", err)
	}

	var res *CommonAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		// Vault returns 404 on LIST when the engine is mounted but has no entries.
		if errors.Is(err, ErrNotFound) {
			return &CommonAPIData{}, nil
		}
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: empty response from %s", UsersEndpoint)
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

// GetRoles List All Roles.
// https://developer.hashicorp.com/vault/api-docs/auth/approle#list-roles
func (h *HCPClient) GetRoles(ctx context.Context) (*CommonAPIData, error) {
	rolesUrl, err := url.JoinPath(h.baseUrl, RolesEndpoint)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build roles URL: %w", err)
	}

	uri, err := url.Parse(rolesUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse roles URL: %w", err)
	}

	var res *CommonAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		// Vault returns 404 on LIST when the engine is mounted but has no entries.
		if errors.Is(err, ErrNotFound) {
			return &CommonAPIData{}, nil
		}
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: empty response from %s", RolesEndpoint)
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

// IsPermissionDenied reports whether Vault denied access to the request.
func IsPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

// IsNotFound reports whether Vault found an empty mounted LIST endpoint.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsNoRoute reports whether Vault says a path is absent or inaccessible.
func IsNoRoute(err error) bool {
	return errors.Is(err, ErrNoRoute)
}

// GetPolicies. List All Policies.
// https://developer.hashicorp.com/vault/api-docs/system/policy
func (h *HCPClient) GetPolicies(ctx context.Context) (*PolicyAPIData, error) {
	res, err := h.getPolicies(ctx, MethodList, PoliciesACLEndpoint)
	if err == nil {
		ctxzap.Extract(ctx).Debug("baton-hashicorp-vault: listed policies", zap.String("endpoint", PoliciesACLEndpoint))
		return res, nil
	}
	if !IsPermissionDenied(err) && !IsNoRoute(err) {
		return nil, err
	}

	res, err = h.getPolicies(ctx, http.MethodGet, policiesEndpoint)
	if err != nil {
		return nil, err
	}
	ctxzap.Extract(ctx).Debug("baton-hashicorp-vault: listed policies", zap.String("endpoint", policiesEndpoint))
	return res, nil
}

func (h *HCPClient) getPolicies(ctx context.Context, method, endpoint string) (*PolicyAPIData, error) {
	policiesUrl, err := url.JoinPath(h.baseUrl, endpoint)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build policies URL: %w", err)
	}

	uri, err := url.Parse(policiesUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse policies URL: %w", err)
	}

	var res *PolicyAPIData
	err = h.getAPIData(ctx,
		method,
		uri,
		&res,
	)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: empty response from %s", endpoint)
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

func (h *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) error {
	var (
		resp *http.Response
		err  error
	)

	token, err := h.ensureValidToken(ctx)
	if err != nil {
		return err
	}

	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to parse request URL %q: %w", endpointUrl, err)
	}

	req, err := h.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		h.requestOptions(token, body)...,
	)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to create %s request for %s: %w", method, endpointUrl, err)
	}

	switch method {
	case MethodList, http.MethodGet:
		resp, err = h.httpClient.Do(req, uhttp.WithResponse(&res))
		if resp != nil {
			defer resp.Body.Close()
		}
	case http.MethodPost:
		if res != nil {
			resp, err = h.httpClient.Do(req, uhttp.WithResponse(&res))
		} else {
			resp, err = h.httpClient.Do(req)
		}
		if resp != nil {
			defer resp.Body.Close()
		}
	default:
		return fmt.Errorf("baton-hashicorp-vault: unsupported HTTP method %q", method)
	}

	if resp != nil && resp.StatusCode == http.StatusNotFound {
		var vaultError struct {
			Errors []string `json:"errors"`
		}
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("baton-hashicorp-vault: failed to read 404 response body: %w", readErr)
		}
		if json.Unmarshal(responseBody, &vaultError) == nil && len(vaultError.Errors) > 0 {
			return fmt.Errorf("baton-hashicorp-vault: %s %s: %s: %w", method, endpointUrl, vaultError.Errors[0], ErrNoRoute)
		}
		return fmt.Errorf("baton-hashicorp-vault: %s %s: %w", method, endpointUrl, ErrNotFound)
	}

	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: %s %s failed: %w", method, endpointUrl, err)
	}

	return nil
}

// LookupSelf returns information about the token authenticating this client.
func (h *HCPClient) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	if h == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: client is nil")
	}

	endpoint, err := url.JoinPath(h.baseUrl, LookupSelfEndpoint)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build lookup-self URL: %w", err)
	}
	var response tokenLookupSelfResponse
	if err := h.doRequest(ctx, http.MethodGet, endpoint, &response, nil); err != nil {
		return nil, err
	}
	return &response.Data, nil
}

// CapabilitiesSelf returns this token's capabilities for each requested Vault path.
func (h *HCPClient) CapabilitiesSelf(ctx context.Context, paths []string) (map[string][]string, error) {
	if h == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: client is nil")
	}

	endpoint, err := url.JoinPath(h.baseUrl, CapabilitiesEndpoint)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build capabilities-self URL: %w", err)
	}
	var response map[string]json.RawMessage
	if err := h.doRequest(ctx, http.MethodPost, endpoint, &response, map[string][]string{"paths": paths}); err != nil {
		return nil, err
	}
	if data, ok := response["data"]; ok {
		var wrapped map[string]json.RawMessage
		if err := json.Unmarshal(data, &wrapped); err == nil && wrapped != nil {
			response = wrapped
		}
	}
	delete(response, "capabilities")

	capabilities := make(map[string][]string, len(paths))
	for _, path := range paths {
		capabilities[path] = []string{"deny"}
		if raw, ok := response[path]; ok {
			var values []string
			if err := json.Unmarshal(raw, &values); err != nil {
				return nil, fmt.Errorf("baton-hashicorp-vault: failed to decode capabilities for %q: %w", path, err)
			}
			capabilities[path] = values
		}
	}
	return capabilities, nil
}

func (h *HCPClient) GetUser(ctx context.Context, name string) (*UserAPIData, error) {
	userUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build URL for user %q: %w", name, err)
	}

	uri, err := url.Parse(userUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse URL for user %q: %w", name, err)
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
	if res == nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: empty response from %s", UsersEndpoint+"/"+name)
	}

	return res, nil
}

func (h *HCPClient) ListAllAuthenticationMethods(ctx context.Context) (*authMethodsAPIData, string, error) {
	authUrl, err := url.JoinPath(h.baseUrl, AuthMethodsEndpoint)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to build auth methods URL: %w", err)
	}

	uri, err := url.Parse(authUrl)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to parse auth methods URL: %w", err)
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
	if res == nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: empty response from %s", AuthMethodsEndpoint)
	}

	return res, "", nil
}

func (h *HCPClient) ListAllGroups(ctx context.Context) (*groupsAPIData, string, error) {
	groupUrl, err := url.JoinPath(h.baseUrl, GroupsEndpoint)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to build groups URL: %w", err)
	}

	uri, err := url.Parse(groupUrl)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to parse groups URL: %w", err)
	}

	var res *groupsAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		// Vault returns 404 on LIST when the engine is mounted but has no entries.
		if errors.Is(err, ErrNotFound) {
			return &groupsAPIData{}, "", nil
		}
		return nil, "", err
	}
	if res == nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: empty response from %s", GroupsEndpoint)
	}

	return res, "", nil
}

func (h *HCPClient) ListAllEntities(ctx context.Context) (*entityAPIData, string, error) {
	entityUrl, err := url.JoinPath(h.baseUrl, EntityEndpoint)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to build entities URL: %w", err)
	}

	uri, err := url.Parse(entityUrl)
	if err != nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: failed to parse entities URL: %w", err)
	}

	var res *entityAPIData
	err = h.getAPIData(ctx,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		// Vault returns 404 on LIST when the engine is mounted but has no entries.
		if errors.Is(err, ErrNotFound) {
			return &entityAPIData{}, "", nil
		}
		return nil, "", err
	}
	if res == nil {
		return nil, "", fmt.Errorf("baton-hashicorp-vault: empty response from %s", EntityEndpoint)
	}

	return res, "", nil
}

// UpdateUserPolicy. Update policies for an existing user.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#update-policies-on-user
func (h *HCPClient) UpdateUserPolicy(ctx context.Context, policy []string, name string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for update user policy %q: %w", name, err)
	}

	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, nil, bodyUpdateUserPolicy{
		TokenPolicies: policy,
	}); err != nil {
		return err
	}

	return nil
}
