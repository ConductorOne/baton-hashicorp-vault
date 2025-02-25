package connector

import (
	"context"
	"regexp"
	"strconv"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func userResource(ctx context.Context, user *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var userStatus v2.UserTrait_Status_Status = v2.UserTrait_Status_STATUS_ENABLED
	profile := map[string]interface{}{
		"user_id":    user.ID,
		"user_name":  user.Name,
		"mount_type": user.MountType,
	}

	userTraits := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(userStatus),
	}

	ret, err := rs.NewUserResource(
		user.Name,
		userResourceType,
		user.ID,
		userTraits,
		rs.WithParentResourceID(parentResourceID))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func roleResource(ctx context.Context, role *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"id":         role.ID,
		"name":       role.Name,
		"mount_type": role.MountType,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	resource, err := rs.NewRoleResource(role.Name, roleResourceType, role.ID, roleTraitOptions)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func policyResource(ctx context.Context, policy *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ResourceOption
	profile := map[string]interface{}{
		"id":         policy.ID,
		"name":       policy.Name,
		"mount_type": policy.MountType,
	}

	policyTraitOptions := []rs.AppTraitOption{
		rs.WithAppProfile(profile),
	}
	opts = append(opts, rs.WithAppTrait(policyTraitOptions...))
	resource, err := rs.NewResource(
		policy.Name,
		policyResourceType,
		policy.ID,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func secretResource(ctx context.Context, secret *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ResourceOption
	profile := map[string]interface{}{
		"id":         secret.ID,
		"name":       secret.Name,
		"mount_type": secret.MountType,
	}

	policyTraitOptions := []rs.AppTraitOption{
		rs.WithAppProfile(profile),
	}
	opts = append(opts, rs.WithAppTrait(policyTraitOptions...))
	resource, err := rs.NewResource(
		secret.Name,
		secretResourceType,
		secret.ID,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func groupResource(ctx context.Context, group *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_name": group.Name,
		"group_id":   group.ID,
	}

	groupTraitOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	resource, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		groupTraitOptions,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

func unmarshalSkipToken(token *pagination.Token) (int32, *pagination.Bag, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(token.Token)
	if err != nil {
		return 0, nil, err
	}
	current := b.Current()
	skip := int32(0)
	if current != nil && current.Token != "" {
		skip64, err := strconv.ParseInt(current.Token, 10, 32)
		if err != nil {
			return 0, nil, err
		}
		skip = int32(skip64)
	}
	return skip, b, nil
}

func RemoveIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func getToken(pToken *pagination.Token, resourceType *v2.ResourceType) (*pagination.Bag, int, error) {
	var pageToken int
	_, bag, err := unmarshalSkipToken(pToken)
	if err != nil {
		return bag, 0, err
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceType.Id,
		})
	}

	if bag.Current().Token != "" {
		pageToken, err = strconv.Atoi(bag.Current().Token)
		if err != nil {
			return bag, 0, err
		}
	}

	return bag, pageToken, nil
}

func authMethodResource(ctx context.Context, secret *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ResourceOption
	profile := map[string]interface{}{
		"id":   secret.ID,
		"name": secret.Name,
	}

	policyTraitOptions := []rs.AppTraitOption{
		rs.WithAppProfile(profile),
	}
	opts = append(opts, rs.WithAppTrait(policyTraitOptions...))
	resource, err := rs.NewResource(
		secret.Name,
		authMethodResourceType,
		secret.ID,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func entityResource(ctx context.Context, entity *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ResourceOption
	profile := map[string]interface{}{
		"id":   entity.ID,
		"name": entity.Name,
	}

	policyTraitOptions := []rs.AppTraitOption{
		rs.WithAppProfile(profile),
	}
	opts = append(opts, rs.WithAppTrait(policyTraitOptions...))
	resource, err := rs.NewResource(
		entity.Name,
		entityResourceType,
		entity.ID,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

func removeTrailingSlash(strPath string) string {
	regex := regexp.MustCompile(`/`)
	return regex.ReplaceAllString(strPath, "")
}
