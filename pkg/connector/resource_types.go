package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

// By default, the number of objects returned per page is 1000.
// https://developer.hashicorp.com/boundary/docs/api-clients/api/pagination
const ITEMSPERPAGE = 1000

var (
	userResourceType = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
	}

	roleResourceType = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Description: "Roles of Hashicorp Vault",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
	}

	policyResourceType = &v2.ResourceType{
		Id:          "policy",
		DisplayName: "Policy",
		Description: "Policy of Hashicorp Vault",
	}

	secretResourceType = &v2.ResourceType{
		Id:          "secret",
		DisplayName: "Secret",
		Description: "Secret of Hashicorp Vault",
	}

	authMethodResourceType = &v2.ResourceType{
		Id:          "auth_method",
		DisplayName: "Authentication Method",
		Description: "Authentication Methods of Hashicorp Vault",
	}

	groupResourceType = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Description: "Group of Hashicorp Vault",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
	}

	entityResourceType = &v2.ResourceType{
		Id:          "entity",
		DisplayName: "Entity",
		Description: "Entity of Hashicorp Vault",
	}
)
