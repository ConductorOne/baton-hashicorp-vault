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

type bodyEnableAuth struct {
	Type string `json:"type"`
}

type bodyUpdateUserPolicy struct {
	TokenPolicies []string `json:"token_policies"`
}
