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

	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Description: "Roles of FreshService",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
	}
)
