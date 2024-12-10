package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type authMethodBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (a *authMethodBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return authMethodResourceType
}

func (a *authMethodBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(pToken, userResourceType)
	if err != nil {
		return nil, "", nil, err
	}

	authMethods, nextPageToken, err := a.client.ListAllAuthenticationMethods(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, "", nil, err
	}

	for method := range authMethods.Data {
		ur, err := authMethodResource(ctx, &client.APIResource{
			ID:   method,
			Name: method,
		}, nil)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextPageToken, nil, nil
}

func (a *authMethodBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (a *authMethodBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newAuthMethodBuilder(c *client.HCPClient) *authMethodBuilder {
	return &authMethodBuilder{
		resourceType: authMethodResourceType,
		client:       c,
	}
}
