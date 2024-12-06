package client

type auth struct {
	bearerToken string
}

type CommonAPIData struct {
	RequestID     string      `json:"request_id,omitempty"`
	LeaseID       string      `json:"lease_id,omitempty"`
	Renewable     bool        `json:"renewable,omitempty"`
	LeaseDuration int         `json:"lease_duration,omitempty"`
	Data          Data        `json:"data,omitempty"`
	WrapInfo      interface{} `json:"wrap_info,omitempty"`
	Warnings      interface{} `json:"warnings,omitempty"`
	Auth          interface{} `json:"auth,omitempty"`
	MountType     string      `json:"mount_type,omitempty"`
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
	Keys          []string    `json:"keys,omitempty"`
	Policies      []string    `json:"policies,omitempty"`
	RequestID     string      `json:"request_id,omitempty"`
	LeaseID       string      `json:"lease_id,omitempty"`
	Renewable     bool        `json:"renewable,omitempty"`
	LeaseDuration int         `json:"lease_duration,omitempty"`
	Data          PolicyData  `json:"data,omitempty"`
	WrapInfo      interface{} `json:"wrap_info,omitempty"`
	Warnings      interface{} `json:"warnings,omitempty"`
	Auth          interface{} `json:"auth,omitempty"`
	MountType     string      `json:"mount_type,omitempty"`
}

type PolicyData struct {
	Keys     []string `json:"keys,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

type UserAPIData struct {
	RequestID     string      `json:"request_id,omitempty"`
	LeaseID       string      `json:"lease_id,omitempty"`
	Renewable     bool        `json:"renewable,omitempty"`
	LeaseDuration int         `json:"lease_duration,omitempty"`
	Data          UserData    `json:"data,omitempty"`
	WrapInfo      interface{} `json:"wrap_info,omitempty"`
	Warnings      interface{} `json:"warnings,omitempty"`
	Auth          interface{} `json:"auth,omitempty"`
	MountType     string      `json:"mount_type,omitempty"`
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
	RequestID     string                 `json:"request_id,omitempty"`
	LeaseID       string                 `json:"lease_id,omitempty"`
	Renewable     bool                   `json:"renewable,omitempty"`
	LeaseDuration int                    `json:"lease_duration,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	WrapInfo      interface{}            `json:"wrap_info,omitempty"`
	Warnings      interface{}            `json:"warnings,omitempty"`
	Auth          interface{}            `json:"auth,omitempty"`
	MountType     string                 `json:"mount_type,omitempty"`
}

type groupsAPIData struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		KeyInfo map[string]group `json:"key_info"`
		Keys    []string         `json:"keys"`
	} `json:"data"`
	WrapInfo  interface{} `json:"wrap_info"`
	Warnings  interface{} `json:"warnings"`
	Auth      interface{} `json:"auth"`
	MountType string      `json:"mount_type"`
}

type group struct {
	Name              string `json:"name"`
	NumMemberEntities int    `json:"num_member_entities"`
	NumParentGroups   int    `json:"num_parent_groups"`
}
