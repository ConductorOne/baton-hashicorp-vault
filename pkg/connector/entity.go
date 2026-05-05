package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type entityBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (e *entityBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return entityResourceType
}

func (e *entityBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(&opts.PageToken, entityResourceType)
	if err != nil {
		return nil, nil, err
	}

	entities, nextPageToken, err := e.client.ListAllEntities(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for entityId, entity := range entities.Data.KeyInfo {
		ur, err := entityResource(ctx, &client.APIResource{
			ID:   entityId,
			Name: entity.Name,
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

func (e *entityBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func (e *entityBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func newEntityBuilder(c *client.HCPClient) *entityBuilder {
	return &entityBuilder{
		resourceType: entityResourceType,
		client:       c,
	}
}
