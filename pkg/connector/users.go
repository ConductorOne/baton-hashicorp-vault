package connector

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// oidcPagePrefix marks page tokens in the OIDC phase; the suffix is an offset
// into the sorted list of OIDC entity IDs. An empty token is the userpass phase.
const oidcPagePrefix = "oidc:"

// List returns userpass users first, then Vault identity entities that logged
// in through an OIDC/JWT auth mount. Vault has no user object for OIDC logins:
// the identity is an entity alias created at login.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: failed to unmarshal pagination token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: userResourceType.Id})
	}

	token := bag.Current().Token
	if strings.HasPrefix(token, oidcPagePrefix) {
		offset, err := strconv.Atoi(strings.TrimPrefix(token, oidcPagePrefix))
		if err != nil || offset < 0 {
			return nil, nil, fmt.Errorf("baton-hashicorp-vault: invalid page token %q", token)
		}
		return u.listOIDC(ctx, bag, offset)
	}

	users, _, err := u.client.ListAllUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	var rv []*v2.Resource
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

	if err := bag.Next(oidcPagePrefix + "0"); err != nil {
		return nil, nil, err
	}
	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return rv, &rsTypes.SyncOpResults{NextPageToken: nextPageToken}, nil
}

func (u *userBuilder) listOIDC(ctx context.Context, bag *pagination.Bag, offset int) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	list, err := u.client.ListEntitiesWithAliases(ctx)
	if err != nil {
		return nil, nil, err
	}

	ids := oidcEntityIDs(list)
	end := offset + oidcPageSize
	next := ""
	if end < len(ids) {
		next = oidcPagePrefix + strconv.Itoa(end)
	} else {
		end = len(ids)
	}
	if offset > end {
		offset = end
	}

	var rv []*v2.Resource
	for _, id := range ids[offset:end] {
		entity, err := u.client.GetEntity(ctx, id)
		if err != nil {
			// The entity was deleted between the list and the read.
			if errors.Is(err, client.ErrNotFound) {
				continue
			}
			return nil, nil, err
		}

		ur, err := oidcUserResource(entity)
		if err != nil {
			return nil, nil, err
		}
		if ur != nil {
			rv = append(rv, ur)
		}
	}

	if err := bag.Next(next); err != nil {
		return nil, nil, err
	}
	nextPageToken := ""
	if next != "" {
		if nextPageToken, err = bag.Marshal(); err != nil {
			return nil, nil, err
		}
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
