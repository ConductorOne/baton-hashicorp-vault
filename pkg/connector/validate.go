package connector

import "slices"

type requiredCapability struct {
	path         string
	capability   string
	resourceType string
}

// requiredCapabilities documents the API access exercised by the current sync.
var requiredCapabilities = []requiredCapability{
	{path: "sys/policies/acl", capability: "list", resourceType: "policy"},
	{path: "sys/policy", capability: "read", resourceType: "policy"},
	{path: "sys/auth", capability: "read", resourceType: "auth_method"},
	{path: "auth/userpass/users", capability: "list", resourceType: "user"},
	{path: "auth/approle/role", capability: "list", resourceType: "role"},
	{path: "identity/entity/id", capability: "list", resourceType: "entity"},
	{path: "identity/group/id", capability: "list", resourceType: "group"},
	{path: "sys/mounts", capability: "read", resourceType: "secret"},
}

func hasCapability(capabilities []string, required string) bool {
	return slices.Contains(capabilities, "root") || slices.Contains(capabilities, required)
}

// missingCapabilities returns one missing resource type at most. Policy access
// is available through either the modern or the legacy policy endpoint.
func missingCapabilities(capabilities map[string][]string) []string {
	missing := make([]string, 0, len(requiredCapabilities))
	policyAvailable := hasCapability(capabilities["sys/policies/acl"], "list") || hasCapability(capabilities["sys/policy"], "read")
	seen := make(map[string]bool)
	for _, required := range requiredCapabilities {
		if required.resourceType == "policy" {
			if !policyAvailable && !seen[required.resourceType] {
				missing = append(missing, required.resourceType)
				seen[required.resourceType] = true
			}
			continue
		}
		if !hasCapability(capabilities[required.path], required.capability) && !seen[required.resourceType] {
			missing = append(missing, required.resourceType)
			seen[required.resourceType] = true
		}
	}
	return missing
}
