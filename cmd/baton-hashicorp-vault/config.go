package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"
)

var (
	VaultTokenField = field.StringField(
		"vault-token",
		field.WithDescription("Vault token for direct authentication"),
	)
	RoleIDField = field.StringField(
		"role-id",
		field.WithDescription("AppRole role ID for Vault AppRole authentication"),
	)
	SecretIDField = field.StringField(
		"secret-id",
		field.WithDescription("AppRole secret ID for Vault AppRole authentication"),
	)
	VaultHostField = field.StringField(
		"vault-host",
		field.WithRequired(true),
		field.WithDescription("Vault address or Host. Ex. http://127.0.0.1:8200"),
	)

	FieldRelationships = []field.SchemaFieldRelationship{
		// Must use either vault-token or role-id (not both, not neither)
		field.FieldsAtLeastOneUsed(VaultTokenField, RoleIDField),
		field.FieldsMutuallyExclusive(VaultTokenField, RoleIDField),
		// role-id and secret-id must be provided together
		field.FieldsRequiredTogether(RoleIDField, SecretIDField),
	}

	// ConfigurationFields defines the external configuration required for the connector to run.
	ConfigurationFields = []field.SchemaField{
		VaultTokenField,
		VaultHostField,
		RoleIDField,
		SecretIDField,
	}
	Configurations = field.NewConfiguration(ConfigurationFields, FieldRelationships...)
)

func ValidateConfig(v *viper.Viper) error {
	return nil
}
