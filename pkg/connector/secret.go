package connector

import (
	"context"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type secretBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (s *secretBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return secretResourceType
}

func (s *secretBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var (
		err error
		rv  []*v2.Resource
	)

	bag, _, err := handleToken(pToken, userResourceType)
	if err != nil {
		return nil, "", nil, err
	}

	secrets, nextPageToken, err := s.client.ListAllSecrets(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	err = bag.Next(nextPageToken)
	if err != nil {
		return nil, "", nil, err
	}

	for _, secret := range secrets.Data.Keys {
		ur, err := secretResource(ctx, &client.APIResource{
			ID:        secret,
			Name:      secret,
			MountType: secrets.MountType,
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

func (s *secretBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (s *secretBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newSecretBuilder(c *client.HCPClient) *secretBuilder {
	return &secretBuilder{
		resourceType: secretResourceType,
		client:       c,
	}
}
