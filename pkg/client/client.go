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
	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName      = "X-Vault-Token"
	DefaultAddress      = "http://127.0.0.1:8200"
	usersEndpoint       = "v1/auth/userpass/users"
	rolesEndpoint       = "v1/auth/approle/role"
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

func (h *HCPClient) ListAllUsers(ctx context.Context, opts PageOptions) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	users, page, err := h.GetUsers(ctx, strconv.Itoa(opts.Page), strconv.Itoa(opts.PerPage))
	if err != nil {
		return nil, "", err
	}

	if page.HasNext() {
		nextPageToken = *page.NextPage
	}

	return users, nextPageToken, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass#list-users
func (h *HCPClient) GetUsers(ctx context.Context, startPage, limitPerPage string) (*CommonAPIData, Page, error) {
	usersUrl, err := url.JoinPath(h.baseUrl, usersEndpoint)
	if err != nil {
		return nil, Page{}, err
	}

	uri, err := url.Parse(usersUrl)
	if err != nil {
		return nil, Page{}, err
	}

	var res *CommonAPIData
	page, err := h.getAPIData(ctx,
		startPage,
		limitPerPage,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, page, err
	}

	return res, page, nil
}

func (h *HCPClient) ListAllRoles(ctx context.Context, opts PageOptions) (*CommonAPIData, string, error) {
	var nextPageToken string = ""
	roles, page, err := h.GetRoles(ctx, strconv.Itoa(opts.Page), strconv.Itoa(opts.PerPage))
	if err != nil {
		return nil, "", err
	}

	if page.HasNext() {
		nextPageToken = *page.NextPage
	}

	return roles, nextPageToken, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/approle#list-roles
func (h *HCPClient) GetRoles(ctx context.Context, startPage, limitPerPage string) (*CommonAPIData, Page, error) {
	rolesUrl, err := url.JoinPath(h.baseUrl, rolesEndpoint)
	if err != nil {
		return nil, Page{}, err
	}

	uri, err := url.Parse(rolesUrl)
	if err != nil {
		return nil, Page{}, err
	}

	var res *CommonAPIData
	page, err := h.getAPIData(ctx,
		startPage,
		limitPerPage,
		MethodList,
		uri,
		&res,
	)
	if err != nil {
		return nil, page, err
	}

	return res, page, nil
}

func (h *HCPClient) ListAllPolicies(ctx context.Context, opts PageOptions) (*PolicyAPIData, string, error) {
	var nextPageToken string = ""
	policies, page, err := h.GetPolicies(ctx, strconv.Itoa(opts.Page), strconv.Itoa(opts.PerPage))
	if err != nil {
		return nil, "", err
	}

	if page.HasNext() {
		nextPageToken = *page.NextPage
	}

	return policies, nextPageToken, nil
}

// GetPolicies. List All Policies.
// https://developer.hashicorp.com/vault/api-docs/system/policy
func (h *HCPClient) GetPolicies(ctx context.Context, startPage, limitPerPage string) (*PolicyAPIData, Page, error) {
	policiesUrl, err := url.JoinPath(h.baseUrl, policiesEndpoint)
	if err != nil {
		return nil, Page{}, err
	}

	uri, err := url.Parse(policiesUrl)
	if err != nil {
		return nil, Page{}, err
	}

	var res *PolicyAPIData
	page, err := h.getAPIData(ctx,
		startPage,
		limitPerPage,
		http.MethodGet,
		uri,
		&res,
	)
	if err != nil {
		return nil, page, err
	}

	return res, page, nil
}

// setRawQuery. Set query parameters.
// page : number for the page (inclusive). If not passed, first page is assumed.
// per_page : Number of items to return. If not passed, a page size of 30 is used.
func setRawQuery(uri *url.URL, sPage string, limitPerPage string) {
	q := uri.Query()
	q.Set("per_page", limitPerPage)
	q.Set("page", sPage)
	uri.RawQuery = q.Encode()
}

func (h *HCPClient) getAPIData(ctx context.Context,
	startPage, limitPerPage, method string,
	uri *url.URL,
	res any,
) (Page, error) {
	var (
		err          error
		page         Page
		IsLastPage   = true
		sPage, nPage = "1", "0"
	)
	if startPage != "0" {
		sPage = startPage
	}

	setRawQuery(uri, sPage, limitPerPage)
	if _, _, err = h.doRequest(ctx, method, uri.String(), &res, nil); err != nil {
		return page, err
	}

	if !IsLastPage {
		page = Page{
			PreviousPage: &sPage,
			NextPage:     &nPage,
		}
	}

	return page, nil
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
