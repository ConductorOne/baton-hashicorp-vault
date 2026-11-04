package connector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// oidcPagePrefix marks page tokens in the OIDC phase; the suffix is the last
// entity ID already emitted, so entities created or deleted between pages
// cannot shift the cursor. An empty token is the userpass phase.
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
		return u.listOIDC(ctx, bag, strings.TrimPrefix(token, oidcPagePrefix))
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

	if err := bag.Next(oidcPagePrefix); err != nil {
		return nil, nil, err
	}
	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return rv, &rsTypes.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// listOIDC emits up to oidcPageSize OIDC/JWT entities with ID greater than
// afterID. Tokens that cannot read identity entities (HTTP 403) skip this
// phase with a warning so existing userpass-only syncs keep working.
func (u *userBuilder) listOIDC(ctx context.Context, bag *pagination.Bag, afterID string) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	list, err := u.client.ListEntitiesWithAliases(ctx)
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			l.Warn("baton-hashicorp-vault: token cannot list identity entities; skipping OIDC/JWT users. Grant list on identity/entity/id and read on identity/entity/id/* to sync them")
			return u.finishOIDC(bag, nil, "")
		}
		return nil, nil, err
	}

	ids := oidcEntityIDs(list)
	start := sort.Search(len(ids), func(i int) bool { return ids[i] > afterID })
	end := start + oidcPageSize
	next := ""
	if end < len(ids) {
		next = oidcPagePrefix + ids[end-1]
	} else {
		end = len(ids)
	}

	var rv []*v2.Resource
	for _, id := range ids[start:end] {
		entity, err := u.client.GetEntity(ctx, id)
		if err != nil {
			// The entity was deleted between the list and the read.
			if errors.Is(err, client.ErrNotFound) {
				l.Debug("baton-hashicorp-vault: entity disappeared during sync, skipping", zap.String("entity_id", id))
				continue
			}
			if status.Code(err) == codes.PermissionDenied {
				l.Warn("baton-hashicorp-vault: token cannot read identity entities; skipping OIDC/JWT users")
				return u.finishOIDC(bag, nil, "")
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

	return u.finishOIDC(bag, rv, next)
}

func (u *userBuilder) finishOIDC(bag *pagination.Bag, rv []*v2.Resource, next string) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	if err := bag.Next(next); err != nil {
		return nil, nil, err
	}
	nextPageToken := ""
	if next != "" {
		var err error
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
