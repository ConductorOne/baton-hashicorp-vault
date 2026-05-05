package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	VaultTokenField = field.StringField(
		"vault-token",
		field.WithDisplayName("Vault Token"),
		field.WithDescription("Vault token for direct authentication"),
		field.WithIsSecret(true),
	)
	RoleIDField = field.StringField(
		"role-id",
		field.WithDisplayName("Role ID"),
		field.WithDescription("AppRole role ID for Vault AppRole authentication"),
	)
	SecretIDField = field.StringField(
		"secret-id",
		field.WithDisplayName("Secret ID"),
		field.WithDescription("AppRole secret ID for Vault AppRole authentication"),
		field.WithIsSecret(true),
	)
	VaultHostField = field.StringField(
		"vault-host",
		field.WithDisplayName("Vault host"),
		field.WithDescription("Vault address or Host. Ex. http://127.0.0.1:8200"),
		field.WithRequired(true),
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
)

//go:generate go run -tags=generate ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("HashiCorp Connector"),
	field.WithHelpUrl("/docs/baton/hashicorp-vault"),
)
