package client

type auth struct {
	bearerToken string
}

type UsersAPIData struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          Data        `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          interface{} `json:"auth"`
	MountType     string      `json:"mount_type"`
}

type Data struct {
	Keys []string `json:"keys"`
}
