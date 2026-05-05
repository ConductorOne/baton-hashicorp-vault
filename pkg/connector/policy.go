package connector

import (
	"context"
	"fmt"
	"slices"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type policyBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (p *policyBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return policyResourceType
}

func (p *policyBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)
	_, bag, err := unmarshalSkipToken(&opts.PageToken)
	if err != nil {
		return nil, nil, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: policyResourceType.Id,
		})
	}

	policies, nextPageToken, err := p.client.ListAllPolicies(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for _, policy := range policies.Data.Policies {
		ur, err := policyResource(ctx, &client.APIResource{
			ID:        policy,
			Name:      policy,
			MountType: policies.MountType,
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

func (p *policyBuilder) Entitlements(_ context.Context, res *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	var rv []*v2.Entitlement
	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDescription(fmt.Sprintf("Assigned to %s policy", res.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s policy %s", res.DisplayName, assignedEntitlement)),
	}
	rv = append(rv, ent.NewAssignmentEntitlement(res, assignedEntitlement, assigmentOptions...))

	return rv, nil, nil
}

func (p *policyBuilder) Grants(ctx context.Context, res *v2.Resource, opts rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Grant
	)
	bag, _, err := getToken(&opts.PageToken, policyResourceType)
	if err != nil {
		return nil, nil, err
	}

	users, nextPageToken, err := p.client.ListAllUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range users.Data.Keys {
		userInfo, err := p.client.GetUser(ctx, user)
		if err != nil {
			return nil, nil, err
		}

		for _, userPolicy := range userInfo.Data.TokenPolicies {
			if userPolicy != res.Id.Resource {
				continue
			}

			g := grant.NewGrant(res, assignedEntitlement, &v2.ResourceId{
				ResourceType: userResourceType.Id,
				Resource:     user,
			})
			rv = append(rv, g)
		}
	}

	nextPageToken, err = bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &rsTypes.SyncOpResults{NextPageToken: nextPageToken}, nil
}

func (p *policyBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-hashicorp-vault: only users can be granted policy membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: only users can be granted policy membership")
	}

	policyId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource
	userInfo, err := p.client.GetUser(ctx, userId)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: failed to get user %q for policy grant: %w", userId, err)
	}

	var policies = []string{}
	policies = append(policies, userInfo.Data.TokenPolicies...)
	posPolicy := slices.IndexFunc(policies, func(c string) bool {
		return c == policyId
	})
	if posPolicy == NF {
		policies = append(policies, policyId)
	}

	err = p.client.UpdateUserPolicy(ctx, policies, userId)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: failed to update policies for user %q: %w", userId, err)
	}

	g := grant.NewGrant(entitlement.Resource, assignedEntitlement, principal.Id)
	return []*v2.Grant{g}, nil, nil
}

func (p *policyBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	principal := grant.Principal
	entitlement := grant.Entitlement
	if principal.Id.ResourceType != userResourceType.Id {
		l.Warn(
			"baton-hashicorp-vault: only users can have policy membership revoked",
			zap.String("principal_id", principal.Id.String()),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("baton-hashicorp-vault: only users can have policy membership revoked")
	}

	userId := principal.Id.Resource
	policyId := entitlement.Resource.Id.Resource
	userInfo, err := p.client.GetUser(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to get user %q for policy revoke: %w", userId, err)
	}

	var policies = []string{}
	policies = append(policies, userInfo.Data.TokenPolicies...)
	posPolicy := slices.IndexFunc(policies, func(c string) bool {
		return c == policyId
	})
	if posPolicy != NF {
		policies = RemoveIndex(policies, posPolicy)
	}

	err = p.client.UpdateUserPolicy(ctx, policies, userId)
	if err != nil {
		return nil, fmt.Errorf("baton-hashicorp-vault: failed to update policies for user %q: %w", userId, err)
	}

	return nil, nil
}

func newPolicyBuilder(c *client.HCPClient) *policyBuilder {
	return &policyBuilder{
		resourceType: policyResourceType,
		client:       c,
	}
}
