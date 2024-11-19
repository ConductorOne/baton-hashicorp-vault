package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

// AuthHeaderName is the name of the header containing the token.
const (
	AuthHeaderName = "X-Vault-Token"
	DefaultAddress = "https://127.0.0.1:8200/v1/auth"
)

type HCPClient struct {
	httpClient *uhttp.BaseHttpClient
	auth       *auth
	baseUrl    string
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
	endpointUrl, err := url.JoinPath(host, "v1/auth")
	if err != nil {
		return h, err
	}

	baseUrl, err := url.Parse(endpointUrl)
	if err != nil {
		return h, err
	}

	h.baseUrl = baseUrl.String()
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

func (h *HCPClient) ListAllUsers(ctx context.Context, opts PageOptions) ([]string, string, error) {
	var nextPageToken string = ""
	users, page, err := h.GetUsers(ctx, strconv.Itoa(opts.Page), strconv.Itoa(opts.PerPage))
	if err != nil {
		return nil, "", err
	}

	if page.HasNext() {
		nextPageToken = *page.NextPage
	}

	return users.Data.Keys, nextPageToken, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass
func (h *HCPClient) GetUsers(ctx context.Context, startPage, limitPerPage string) (*UsersAPIData, Page, error) {
	usersUrl, err := url.JoinPath(h.baseUrl, "userpass/users")
	if err != nil {
		return nil, Page{}, err
	}

	uri, err := url.Parse(usersUrl)
	if err != nil {
		return nil, Page{}, err
	}

	var res *UsersAPIData
	page, err := h.getAPIData(ctx,
		startPage,
		limitPerPage,
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
	startPage string,
	limitPerPage string,
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
	if _, _, err = h.doRequest(ctx, "LIST", uri.String(), &res, nil); err != nil {
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
	case "LIST":
		resp, err = h.httpClient.Do(req, uhttp.WithResponse(&res))
		defer resp.Body.Close()
	case http.MethodPatch:
		resp, err = h.httpClient.Do(req)
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, nil, err
	}

	return resp.Header, resp.StatusCode, nil
}
