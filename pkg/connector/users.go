package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(&opts.PageToken, userResourceType)
	if err != nil {
		return nil, nil, err
	}

	users, nextPageToken, err := u.client.ListAllUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range users.Data.Keys {
		ur, err := userResource(ctx, &client.APIResource{
			ID:        user,
			Name:      user,
			MountType: users.MountType,
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

// Entitlements always returns an empty slice for users.
func (u *userBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (u *userBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func newUserBuilder(c *client.HCPClient) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       c,
	}
}
