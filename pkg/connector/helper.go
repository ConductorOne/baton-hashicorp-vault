package connector

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func userResource(_ context.Context, user *client.APIResource, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	userStatus := v2.UserTrait_Status_STATUS_ENABLED
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

// oidcUserResource builds a user from an entity's OIDC/JWT aliases. The entity
// ID is the resource ID: it is stable, unlike the alias name or email.
func oidcUserResource(entity *client.Entity) (*v2.Resource, error) {
	aliases := oidcAliases(entity.Aliases)
	if len(aliases) == 0 {
		return nil, nil
	}

	email := oidcEmail(entity, aliases)
	login := aliases[0].Name
	displayName := entity.Name
	if displayName == "" {
		displayName = login
	}

	status := v2.UserTrait_Status_STATUS_ENABLED
	if entity.Disabled {
		status = v2.UserTrait_Status_STATUS_DISABLED
	}

	profile := map[string]interface{}{
		"entity_id":  entity.ID,
		"user_name":  login,
		"mount_type": aliases[0].MountType,
		"mount_path": aliases[0].MountPath,
	}

	if email != "" {
		profile["email"] = email
	}

	traits := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(status),
		rs.WithUserLogin(login),
	}
	if email != "" {
		traits = append(traits, rs.WithEmail(email, true))
	}

	return rs.NewUserResource(displayName, userResourceType, entity.ID, traits)
}

func roleResource(_ context.Context, role *client.APIResource) (*v2.Resource, error) {
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

func policyResource(_ context.Context, policy *client.APIResource) (*v2.Resource, error) {
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

func secretResource(_ context.Context, secret *client.APIResource) (*v2.Resource, error) {
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

func groupResource(_ context.Context, group *client.APIResource) (*v2.Resource, error) {
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
		return 0, nil, fmt.Errorf("baton-hashicorp-vault: failed to unmarshal pagination token: %w", err)
	}
	current := b.Current()
	skip := int32(0)
	if current != nil && current.Token != "" {
		skip64, err := strconv.ParseInt(current.Token, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("baton-hashicorp-vault: invalid skip token %q: %w", current.Token, err)
		}
		skip = int32(skip64)
	}
	return skip, b, nil
}

func removeIndex(s []string, index int) []string {
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
			return bag, 0, fmt.Errorf("baton-hashicorp-vault: invalid page token %q: %w", bag.Current().Token, err)
		}
	}

	return bag, pageToken, nil
}

func authMethodResource(_ context.Context, secret *client.APIResource) (*v2.Resource, error) {
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

func entityResource(_ context.Context, entity *client.APIResource) (*v2.Resource, error) {
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
