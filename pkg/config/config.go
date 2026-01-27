package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	VaultToken = field.StringField(
		"vault-token",
		field.WithRequired(true),
		field.WithDescription("Vault Token"),
		field.WithIsSecret(true),
		field.WithDisplayName("Vault Token"),
	)
	VaultHost = field.StringField(
		"vault-host",
		field.WithRequired(true),
		field.WithDescription("Vault address or Host. Ex. http://127.0.0.1:8200"),
		field.WithDisplayName("Vault Host"),
	)

	// FieldRelationships defines relationships between the fields.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

//go:generate go run ./gen
var Configuration = field.NewConfiguration([]field.SchemaField{
	VaultToken,
	VaultHost,
}, field.WithConstraints(FieldRelationships...))
