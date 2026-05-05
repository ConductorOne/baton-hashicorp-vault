package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type groupBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (g *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return groupResourceType
}

func (g *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(&opts.PageToken, groupResourceType)
	if err != nil {
		return nil, nil, err
	}

	groups, nextPageToken, err := g.client.ListAllGroups(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for groupId, group := range groups.Data.KeyInfo {
		ur, err := groupResource(ctx, &client.APIResource{
			ID:   groupId,
			Name: group.Name,
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

func (g *groupBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func (g *groupBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func newGroupBuilder(c *client.HCPClient) *groupBuilder {
	return &groupBuilder{
		resourceType: groupResourceType,
		client:       c,
	}
}
