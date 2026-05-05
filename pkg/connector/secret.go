package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type secretBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (s *secretBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return secretResourceType
}

func (s *secretBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := getToken(&opts.PageToken, secretResourceType)
	if err != nil {
		return nil, nil, err
	}

	secrets, nextPageToken, err := s.client.ListAllSecrets(ctx, bag.Current().Token)
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, nil, err
	}

	for _, secret := range secrets.Data.Keys {
		ur, err := secretResource(ctx, &client.APIResource{
			ID:        secret,
			Name:      secret,
			MountType: secrets.MountType,
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

func (s *secretBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Entitlement, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func (s *secretBuilder) Grants(_ context.Context, _ *v2.Resource, _ rsTypes.SyncOpAttrs) ([]*v2.Grant, *rsTypes.SyncOpResults, error) {
	return nil, nil, nil
}

func newSecretBuilder(c *client.HCPClient) *secretBuilder {
	return &secretBuilder{
		resourceType: secretResourceType,
		client:       c,
	}
}
