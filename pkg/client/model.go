package client

import "time"

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

type bodyUsers struct {
	Password        string   `json:"password"`
	TokenPolicies   []string `json:"token_policies"`
	TokenBoundCidrs []string `json:"token_bound_cidrs"`
}

type bodyRoles struct {
	TokenType     string   `json:"token_type"`
	TokenTTL      string   `json:"token_ttl"`
	TokenMaxTTL   string   `json:"token_max_ttl"`
	TokenPolicies []string `json:"token_policies"`
	Period        int      `json:"period"`
	BindSecretID  bool     `json:"bind_secret_id"`
}

type BodyEnableAuth struct {
	Type string `json:"type"`
}

type bodyUpdateUserPolicy struct {
	TokenPolicies []string `json:"token_policies"`
}

type BodySecret struct {
	Type                  string  `json:"type"`
	Description           string  `json:"description"`
	Config                Config  `json:"config"`
	Local                 bool    `json:"local"`
	SealWrap              bool    `json:"seal_wrap"`
	ExternalEntropyAccess bool    `json:"external_entropy_access"`
	Options               Options `json:"options"`
}

type Config struct {
	Options         interface{} `json:"options"`
	DefaultLeaseTTL string      `json:"default_lease_ttl"`
	MaxLeaseTTL     string      `json:"max_lease_ttl"`
	ForceNoCache    bool        `json:"force_no_cache"`
}

type Options struct {
	Version string `json:"version"`
}

type bodySecrets struct {
	MyValue string `json:"my-value"`
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

// Identity entity types. Vault has no native email attribute: OIDC/JWT logins
// create an entity alias whose name is the user_claim value, and any other
// claims are copied into the alias metadata only if the operator configured
// claim_mappings on the role.

// EntityListData is the data envelope of LIST identity/entity/id.
type EntityListData struct {
	Keys    []string              `json:"keys,omitempty"`
	KeyInfo map[string]EntityInfo `json:"key_info,omitempty"`
}

// EntityInfo is the per-entity summary returned by the list endpoint.
type EntityInfo struct {
	Name     string        `json:"name,omitempty"`
	Disabled bool          `json:"disabled,omitempty"`
	Aliases  []EntityAlias `json:"aliases,omitempty"`
}

// EntityAlias links an entity to an identity in an auth mount.
type EntityAlias struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name,omitempty"`
	MountType      string            `json:"mount_type,omitempty"`
	MountPath      string            `json:"mount_path,omitempty"`
	MountAccessor  string            `json:"mount_accessor,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// Entity is the response of GET identity/entity/id/:id.
type Entity struct {
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	Disabled bool              `json:"disabled,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Aliases  []EntityAlias     `json:"aliases,omitempty"`
}

type entityReadAPIData struct {
	Data Entity `json:"data,omitempty"`
}

type entityListAPIData struct {
	Data EntityListData `json:"data,omitempty"`
}
