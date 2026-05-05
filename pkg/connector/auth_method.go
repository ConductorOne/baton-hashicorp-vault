package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type authMethodBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (a *authMethodBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return authMethodResourceType
}

func (a *authMethodBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(&opts.PageToken, authMethodResourceType)
	if err != nil {
		return nil, nil, err
	}

	authMethods, nextPageToken, err := a.client.ListAllAuthenticationMethods(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for method := range authMethods.Data {
		ur, err := authMethodResource(ctx, &client.APIResource{
			ID:   removeTrailingSlash(method),
			Name: removeTrailingSlash(method),
		}, nil)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &rsTypes.SyncOpResults{NextPageToken: nextPageToken}, nil
}

func (a *authMethodBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func (a *authMethodBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func newAuthMethodBuilder(c *client.HCPClient) *authMethodBuilder {
	return &authMethodBuilder{
		resourceType: authMethodResourceType,
		client:       c,
	}
}
