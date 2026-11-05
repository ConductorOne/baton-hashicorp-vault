package client

import "time"

// KVMount describes a Vault KV engine discovered from sys/mounts.
type KVMount struct {
	Path    string
	Version int
}

type auth struct {
	bearerToken string
	roleID      string
	secretID    string
	expiresAt   time.Time
}

type appRoleLoginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

type appRoleLoginResponse struct {
	Auth appRoleAuth `json:"auth"`
}

type appRoleAuth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
}

// TokenInfo describes the token returned by Vault's lookup-self endpoint.
type TokenInfo struct {
	DisplayName   string   `json:"display_name"`
	Policies      []string `json:"policies"`
	TTL           int      `json:"ttl"`
	Renewable     bool     `json:"renewable"`
	NamespacePath string   `json:"namespace_path"`
}

type tokenLookupSelfResponse struct {
	Data TokenInfo `json:"data"`
}

type CommonAPIData struct {
	RequestID string `json:"request_id,omitempty"`
	Data      Data   `json:"data,omitempty"`
	MountType string `json:"mount_type,omitempty"`
}

type Data struct {
	Keys []string `json:"keys,omitempty"`
}

type APIResource struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	MountType string `json:"mount_type,omitempty"`
	Mount     string `json:"mount,omitempty"`
	KVVersion int    `json:"kv_version,omitempty"`
	Path      string `json:"path,omitempty"`
}

type PolicyAPIData struct {
	Keys      []string   `json:"keys,omitempty"`
	Policies  []string   `json:"policies,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
	Data      PolicyData `json:"data,omitempty"`
	MountType string     `json:"mount_type,omitempty"`
}

type PolicyData struct {
	Keys     []string `json:"keys,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

// Names returns policy names from the first populated Vault response shape.
func (p *PolicyAPIData) Names() []string {
	if p == nil {
		return nil
	}
	for _, names := range [][]string{p.Data.Keys, p.Data.Policies, p.Keys, p.Policies} {
		if len(names) > 0 {
			return names
		}
	}
	return nil
}

type UserAPIData struct {
	RequestID string   `json:"request_id,omitempty"`
	Data      UserData `json:"data,omitempty"`
	MountType string   `json:"mount_type,omitempty"`
}

type UserData struct {
	TokenBoundCidrs      []string `json:"token_bound_cidrs,omitempty"`
	TokenExplicitMaxTTL  int      `json:"token_explicit_max_ttl,omitempty"`
	TokenMaxTTL          int      `json:"token_max_ttl,omitempty"`
	TokenNoDefaultPolicy bool     `json:"token_no_default_policy,omitempty"`
	TokenNumUses         int      `json:"token_num_uses,omitempty"`
	TokenPeriod          int      `json:"token_period,omitempty"`
	TokenPolicies        []string `json:"token_policies,omitempty"`
	TokenTTL             int      `json:"token_ttl,omitempty"`
	TokenType            string   `json:"token_type,omitempty"`
}

type bodyUpdateUserPolicy struct {
	TokenPolicies []string `json:"token_policies"`
}

type authMethodsAPIData struct {
	RequestID string                 `json:"request_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	MountType string                 `json:"mount_type,omitempty"`
}

type groupsAPIData struct {
	RequestID string      `json:"request_id,omitempty"`
	Data      genericData `json:"data,omitempty"`
	MountType string      `json:"mount_type,omitempty"`
}

type group struct {
	Name              string `json:"name,omitempty"`
	NumMemberEntities int    `json:"num_member_entities,omitempty"`
	NumParentGroups   int    `json:"num_parent_groups,omitempty"`
}

type entityAPIData struct {
	RequestID string      `json:"request_id,omitempty"`
	Data      genericData `json:"data,omitempty"`
	Auth      any         `json:"auth,omitempty"`
	MountType string      `json:"mount_type,omitempty"`
}

type genericData struct {
	KeyInfo map[string]group `json:"key_info,omitempty"`
	Keys    []string         `json:"keys,omitempty"`
}
