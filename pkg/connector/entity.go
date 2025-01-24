package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type entityBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (e *entityBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return entityResourceType
}

func (e *entityBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(pToken, entityResourceType)
	if err != nil {
		return nil, "", nil, err
	}

	entities, nextPageToken, err := e.client.ListAllEntities(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, "", nil, err
	}

	for entityId, entity := range entities.Data.KeyInfo {
		ur, err := entityResource(ctx, &client.APIResource{
			ID:   entityId,
			Name: entity.Name,
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

func (e *entityBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (e *entityBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newEntityBuilder(c *client.HCPClient) *entityBuilder {
	return &entityBuilder{
		resourceType: entityResourceType,
		client:       c,
	}
}
