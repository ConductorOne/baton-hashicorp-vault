package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rsTypes "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const maxSecretDepth = 10

type secretBuilder struct {
	resourceType *v2.ResourceType
	client       *client.HCPClient
}

func (s *secretBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return secretResourceType
}

func (s *secretBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rsTypes.SyncOpAttrs) ([]*v2.Resource, *rsTypes.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(opts.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("baton-hashicorp-vault: failed to unmarshal pagination token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: secretResourceType.Id})
	}

	mounts, err := s.client.ListKVMounts(ctx)
	if err != nil {
		if skippable(ctx, err, secretResourceType.Id) {
			return nil, &rsTypes.SyncOpResults{}, nil
		}
		return nil, nil, err
	}
	if len(mounts) == 0 {
		return nil, &rsTypes.SyncOpResults{}, nil
	}

	index := 0
	if token := bag.Current().Token; token != "" {
		index = -1
		for i, mount := range mounts {
			if mount.Path == token {
				index = i
				break
			}
		}
		if index == -1 {
			return nil, nil, fmt.Errorf("baton-hashicorp-vault: unknown KV mount %q in pagination token", token)
		}
	}

	mount := mounts[index]
	paths, err := s.client.ListSecretPaths(ctx, mount, maxSecretDepth)
	if err != nil {
		if skippable(ctx, err, secretResourceType.Id) {
			ctxzap.Extract(ctx).Warn("baton-hashicorp-vault: skipping KV mount", zap.String("mount", mount.Path), zap.Error(err))
			paths = nil
		} else {
			return nil, nil, err
		}
	}

	rv := make([]*v2.Resource, 0, len(paths))
	for _, path := range paths {
		name := mount.Path + path
		ur, err := secretResource(ctx, &client.APIResource{
			ID:        name,
			Name:      name,
			Mount:     mount.Path,
			KVVersion: mount.Version,
			Path:      path,
		})
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	nextMount := ""
	if index+1 < len(mounts) {
		nextMount = mounts[index+1].Path
	}
	if err := bag.Next(nextMount); err != nil {
		return nil, nil, err
	}
	nextPageToken, err := bag.Marshal()
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
