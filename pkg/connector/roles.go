package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

const (
	assignedEntitlement = "assigned"
	NF                  = -1
)

func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return roleResourceType
}

func (r *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)
	bag, _, err := getToken(&opts.PageToken, roleResourceType)
	if err != nil {
		return nil, nil, err
	}

	roles, nextPageToken, err := r.client.ListAllRoles(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range roles.Data.Keys {
		ur, err := roleResource(ctx, &client.APIResource{
			ID:        user,
			Name:      user,
			MountType: roles.MountType,
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

func (r *roleBuilder) Entitlements(_ context.Context, res *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	var rv []*v2.Entitlement
	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDescription(fmt.Sprintf("Assigned to %s role", res.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s role %s", res.DisplayName, assignedEntitlement)),
	}
	rv = append(rv, ent.NewAssignmentEntitlement(res, assignedEntitlement, assigmentOptions...))

	return rv, nil, nil
}

func (r *roleBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	return nil, nil, nil
}

func (r *roleBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	return nil, nil
}

func newRoleBuilder(c *client.HCPClient) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       c,
	}
}
