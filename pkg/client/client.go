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

func (f *HCPClient) WithBearerToken(apiToken string) *HCPClient {
	f.auth.bearerToken = apiToken
	return f
}

func (f *HCPClient) getToken() string {
	return f.auth.bearerToken
}

func isValidUrl(baseUrl string) bool {
	u, err := url.Parse(baseUrl)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func New(ctx context.Context, freshServiceClient *HCPClient) (*HCPClient, error) {
	var (
		clientToken = freshServiceClient.getToken()
		baseUrl     = "http://127.0.0.1:8200/v1/auth"
	)
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	cli, err := uhttp.NewBaseHttpClientWithContext(context.Background(), httpClient)
	if err != nil {
		return freshServiceClient, err
	}

	if freshServiceClient.baseUrl != "" {
		baseUrl = freshServiceClient.baseUrl
	}

	if !isValidUrl(baseUrl) {
		return nil, fmt.Errorf("the url : %s is not valid", baseUrl)
	}

	// bearerToken
	fs := HCPClient{
		httpClient: cli,
		baseUrl:    baseUrl,
		auth: &auth{
			bearerToken: clientToken,
		},
	}

	return &fs, nil
}

func (f *HCPClient) ListAllUsers(ctx context.Context, opts PageOptions) (*UsersAPIData, string, error) {
	var nextPageToken string = ""
	users, page, err := f.GetUsers(ctx, strconv.Itoa(opts.Page), strconv.Itoa(opts.PerPage))
	if err != nil {
		return nil, "", err
	}

	if page.HasNext() {
		nextPageToken = *page.NextPage
	}

	return users, nextPageToken, nil
}

// GetUsers. List All Users.
// https://developer.hashicorp.com/vault/api-docs/auth/userpass
func (f *HCPClient) GetUsers(ctx context.Context, startPage, limitPerPage string) (*UsersAPIData, Page, error) {
	agentsUrl, err := url.JoinPath(f.baseUrl, "userpass/users")
	if err != nil {
		return nil, Page{}, err
	}

	uri, err := url.Parse(agentsUrl)
	if err != nil {
		return nil, Page{}, err
	}

	var res *UsersAPIData
	page, err := f.getAPIData(ctx,
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

func (f *HCPClient) getAPIData(ctx context.Context,
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
	if err, _, _ = f.doRequest(ctx, http.MethodGet, uri.String(), &res, nil); err != nil {
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

func (f *HCPClient) doRequest(ctx context.Context, method, endpointUrl string, res interface{}, body interface{}) (error, http.Header, any) {
	var (
		resp *http.Response
		err  error
	)
	urlAddress, err := url.Parse(endpointUrl)
	if err != nil {
		return err, nil, nil
	}

	req, err := f.httpClient.NewRequest(ctx,
		method,
		urlAddress,
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithJSONBody(body),
	)
	if err != nil {
		return err, nil, nil
	}

	switch method {
	case http.MethodGet:
		resp, err = f.httpClient.Do(req, uhttp.WithResponse(&res))
		defer resp.Body.Close()
	case http.MethodPatch:
		resp, err = f.httpClient.Do(req)
		defer resp.Body.Close()
	}

	if err != nil {
		return err, nil, nil
	}

	return nil, resp.Header, resp.StatusCode
}
