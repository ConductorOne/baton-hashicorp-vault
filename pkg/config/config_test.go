package config

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/test"
)

func TestConfigs(t *testing.T) {
	configurationSchema := field.NewConfiguration(
		ConfigurationFields,
		field.WithConstraints(FieldRelationships...),
	)

	testCases := []test.TestCase{
		{
			Message: "token auth is valid",
			Configs: map[string]string{
				"vault-host":  "http://127.0.0.1:8200",
				"vault-token": "hvs.abc123",
			},
			IsValid: true,
		},
		{
			Message: "approle auth is valid",
			Configs: map[string]string{
				"vault-host": "http://127.0.0.1:8200",
				"role-id":    "my-role",
				"secret-id":  "my-secret",
			},
			IsValid: true,
		},
		{
			Message: "token and approle are mutually exclusive",
			Configs: map[string]string{
				"vault-host":  "http://127.0.0.1:8200",
				"vault-token": "hvs.abc123",
				"role-id":     "my-role",
				"secret-id":   "my-secret",
			},
			IsValid: false,
		},
		{
			Message: "role-id requires secret-id",
			Configs: map[string]string{
				"vault-host": "http://127.0.0.1:8200",
				"role-id":    "my-role",
			},
			IsValid: false,
		},
		{
			Message: "secret-id requires role-id",
			Configs: map[string]string{
				"vault-host": "http://127.0.0.1:8200",
				"secret-id":  "my-secret",
			},
			IsValid: false,
		},
		{
			Message: "at least one auth method is required",
			Configs: map[string]string{
				"vault-host": "http://127.0.0.1:8200",
			},
			IsValid: false,
		},
		{
			Message: "vault-host is required",
			Configs: map[string]string{
				"vault-token": "hvs.abc123",
			},
			IsValid: false,
		},
	}

	test.ExerciseTestCases(t, configurationSchema, nil, testCases)
}
