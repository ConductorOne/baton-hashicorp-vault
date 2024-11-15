package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/spf13/viper"
)

var (
	VaultTokenField = field.StringField(
		"x-vault-token",
		field.WithRequired(true),
		field.WithDescription("Vault Token"),
	)
	VaultHostField = field.StringField(
		"x-vault-host",
		field.WithRequired(true),
		field.WithDescription("Vault Host"),
	)

	FieldRelationships = []field.SchemaFieldRelationship{}

	// ConfigurationFields defines the external configuration required for the connector to run.
	ConfigurationFields = []field.SchemaField{
		VaultTokenField,
		VaultHostField,
	}
	Configurations = field.NewConfiguration(ConfigurationFields)
)

func ValidateConfig(v *viper.Viper) error {
	return nil
}
