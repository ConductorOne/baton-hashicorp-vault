package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotFound is returned when Vault responds with 404. For LIST operations
// this means the path is mounted but has no entries; callers that expect a
// collection should convert it to an empty result. All other callers should
// treat it as a real error.
var ErrNotFound = errors.New("baton-hashicorp-vault: resource not found")

const (
	AuthHeaderName          = "X-Vault-Token"
	DefaultAddress          = "http://127.0.0.1:8200"
	UsersEndpoint           = "v1/auth/userpass/users"
	RolesEndpoint           = "v1/auth/approle/role"
	KvEndpoint              = "v1/kv"
	SecEndpoint             = "v1/secret/metadata"
	AuthMethodsEndpoint     = "v1/sys/auth"
	GroupsEndpoint          = "v1/identity/group/id"
	EntityEndpoint          = "v1/identity/entity/id"
	policiesEndpoint        = "v1/sys/policy"
	ApproleAuthEndpoint     = "v1/sys/auth/approle"
	UserAuthEndpoint        = "v1/sys/auth/userpass"
	KvAuthEndpoint          = "v1/sys/mounts/kv"
	AppRoleLoginEndpoint    = "v1/auth/approle/login"
	LookupSelfEndpoint = "v1/auth/token/lookup-self"
	MethodList              = "LIST"
	approleType             = "approle"
	userpassType            = "userpass"
	kvType                  = "kv"
	StatusBadRequest        = "400 Bad Request"
)

var listEndpoints = []string{KvEndpoint, SecEndpoint}

type HCPClient struct {
	httpClient         *uhttp.BaseHttpClient
	auth               *auth
	baseUrl            string
	mu                 sync.Mutex
	skipMountBootstrap bool
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

func (h *HCPClient) WithAppRole(roleID, secretID string) {
	h.auth.roleID = roleID
	h.auth.secretID = secretID
}

func (h *HCPClient) WithSkipMountBootstrap(skip bool) {
	h.skipMountBootstrap = skip
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
		uhttp.WithJSONBody(appRoleLoginRequest{
			RoleID:   h.auth.roleID,
			SecretID: h.auth.secretID,
		}),
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
	return h.auth.bearerToken
}

// ensureValidToken refreshes the AppRole token if it has expired or is about to.
// Static bearer token auth (no roleID/secretID) is unmanaged and returned as-is.
func (h *HCPClient) ensureValidToken(ctx context.Context) error {
	if h.auth.roleID == "" || h.auth.secretID == "" {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// expiresAt zero means no TTL (e.g. root token) — treat as non-expiring.
	if h.auth.bearerToken != "" && (h.auth.expiresAt.IsZero() || time.Now().UTC().Before(h.auth.expiresAt)) {
		return nil
	}

	return h.appRoleLogin(ctx)
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

	cli, err := uhttp.NewBaseHttpClientWithContext(context.Background(), httpClient)
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
		httpClient:         cli,
		baseUrl:            baseUrl,
		skipMountBootstrap: hcpClient.skipMountBootstrap,
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

	if !hcp.skipMountBootstrap {
		err = enableStores(ctx, &hcp)
		if err != nil {
			return nil, err
		}
	}

	return &hcp, nil
}

func enableStores(ctx context.Context, hcpClient *HCPClient) error {
	if err := ensureMount(ctx, hcpClient, ApproleAuthEndpoint, BodyEnableAuth{Type: approleType}); err != nil {
		return err
	}

	if err := ensureMount(ctx, hcpClient, UserAuthEndpoint, BodyEnableAuth{Type: userpassType}); err != nil {
		return err
	}

	if err := ensureMount(ctx, hcpClient, KvAuthEndpoint, BodySecret{Type: kvType}); err != nil {
		return err
	}

	return nil
}

// ensureMount checks whether a mount exists at path and creates it if not.
// There are three outcomes:
//   - Vault reports the mount missing (400 Bad Request, or a 404 that
//     short-circuits to ErrNotFound): attempt to create it.
//   - 403 (PermissionDenied): warn and assume the mount is already
//     configured, rather than blocking connector startup - see below.
//   - Anything else, including 401 (Unauthenticated - the token itself is
//     invalid, not just under-scoped) and 429/5xx: a genuine failure,
//     returned as-is. uhttp maps 429, 502, 503, and every other 5xx to the
//     same codes.Unavailable, so there's no reliable way to special-case
//     "transient" upstream failures here without also silently swallowing a
//     genuine Vault outage or internal error - keep those loud.
func ensureMount(ctx context.Context, hcpClient *HCPClient, path string, body any) error {
	err := hcpClient.CheckAuthenticationMethod(ctx, path)
	if err == nil {
		return nil
	}

	if strings.Contains(err.Error(), StatusBadRequest) || errors.Is(err, ErrNotFound) {
		if err := hcpClient.EnableAuthMethod(ctx, path, body); err != nil {
			return fmt.Errorf("baton-hashicorp-vault: failed to enable mount %q: %w", path, err)
		}
		return nil
	}

	// Checking (and creating) a mount requires sudo capability in Vault, so a
	// least-privilege, sync-only token will always get 403 here even when the
	// mount already exists and everything else works fine - that's customer
	// config, not a connector bug.
	if status.Code(err) == codes.PermissionDenied {
		ctxzap.Extract(ctx).Warn(
			"baton-hashicorp-vault: unable to verify mount is enabled, assuming it is already configured",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil
	}

	return fmt.Errorf("baton-hashicorp-vault: failed to check mount %q: %w", path, err)
}

func (h *HCPClient) CheckAuthenticationMethod(ctx context.Context, authMethod string) error {
	authUrl, err := url.JoinPath(h.baseUrl, authMethod)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for auth method %q: %w", authMethod, err)
	}

	uri, err := url.Parse(authUrl)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to parse URL for auth method %q: %w", authMethod, err)
	}

	return h.getAPIData(ctx,
		http.MethodGet,
		uri,
		nil,
	)
}

// LookupSelfToken exercises the current bearer token against Vault's
// lookup-self endpoint, which any valid token can call regardless of policy.
// Vault returns 403 for both an under-scoped token AND an invalid/expired
// one, so the mount-bootstrap check alone can't distinguish "this token
// works but lacks sudo" from "this token doesn't work at all" - this gives a
// definitive, capability-independent answer for credential validation.
func (h *HCPClient) LookupSelfToken(ctx context.Context) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, LookupSelfEndpoint)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for token lookup-self: %w", err)
	}

	uri, err := url.Parse(endpointUrl)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to parse URL for token lookup-self: %w", err)
	}

	return h.getAPIData(ctx,
		http.MethodGet,
		uri,
		nil,
	)
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
			return nil, "", fmt.Errorf("baton-hashicorp-vault: invalid pagination token %q: %w", token, err)
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
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build secrets URL: %w", err)
	}

	uri, err := url.Parse(secretsUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse secrets URL: %w", err)
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

	return res, nil
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
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to build policies URL: %w", err)
	}

	uri, err := url.Parse(policiesUrl)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to parse policies URL: %w", err)
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
		return CustomErr{}, fmt.Errorf("baton-hashicorp-vault: failed to read error response body: %w", err)
	}

	var cErr CustomErr
	err = json.Unmarshal(bytes, &cErr)
	if err != nil {
		return cErr, fmt.Errorf("baton-hashicorp-vault: failed to parse error response: %w", err)
	}

	return cErr, nil
}

func (h *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) error {
	var (
		resp *http.Response
		err  error
	)

	if err = h.ensureValidToken(ctx); err != nil {
		return err
	}

	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to parse request URL %q: %w", endpointUrl, err)
	}

	req, err := h.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		uhttp.WithHeader(AuthHeaderName, h.getToken()),
		uhttp.WithJSONBody(body),
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
		resp, err = h.httpClient.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
	}

	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}

	if resp != nil && resp.StatusCode == http.StatusBadRequest {
		cErr, err := getError(resp)
		if err != nil {
			return err
		}

		// It's already authorized / path already in use.
		if len(cErr.Errors) == 0 || strings.Contains(cErr.Errors[0], "path is already in use") {
			return nil
		}
	}

	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: %s %s failed: %w", method, endpointUrl, err)
	}

	return nil
}

// EnableAuthMethod. Enables you to use an auth method.
// https://developer.hashicorp.com/vault/docs/auth
// https://developer.hashicorp.com/vault/docs/auth/approle#via-the-api-1
func (h *HCPClient) EnableAuthMethod(ctx context.Context, apiUrl string, body any) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, apiUrl)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for enable auth method %q: %w", apiUrl, err)
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
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add user %q: %w", name, err)
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
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add role %q: %w", name, err)
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
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for add secret %q: %w", name, err)
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

	return res, "", nil
}

// UpdateUserPolicy. Update policies for an existing user.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#update-policies-on-user
func (h *HCPClient) UpdateUserPolicy(ctx context.Context, policy []string, name string) error {
	endpointUrl, err := url.JoinPath(h.baseUrl, UsersEndpoint, name)
	if err != nil {
		return fmt.Errorf("baton-hashicorp-vault: failed to build URL for update user policy %q: %w", name, err)
	}

	var res any
	if err = h.doRequest(ctx, http.MethodPost, endpointUrl, &res, bodyUpdateUserPolicy{
		TokenPolicies: policy,
	}); err != nil {
		return err
	}

	return nil
}
