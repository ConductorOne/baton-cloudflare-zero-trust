package config

//go:generate go run ./gen

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	AccountIdField = field.StringField(
		"account-id",
		field.WithDisplayName("Account ID"),
		field.WithDescription("Cloudflare account ID"),
		field.WithRequired(true),
	)
	ApiKeyField = field.StringField(
		"api-key",
		field.WithDisplayName("API Key"),
		field.WithDescription("Cloudflare API key"),
		field.WithIsSecret(true),
	)
	ApiTokenField = field.StringField(
		"api-token",
		field.WithDisplayName("API Token"),
		field.WithDescription("Cloudflare API token"),
		field.WithIsSecret(true),
	)
	EmailField = field.StringField(
		"email",
		field.WithDisplayName("Email"),
		field.WithDescription("Cloudflare account email"),
	)

	// FieldRelationships defines relationships between the fields.
	FieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsAtLeastOneUsed(ApiTokenField, ApiKeyField),
		field.FieldsMutuallyExclusive(ApiTokenField, ApiKeyField),
		field.FieldsDependentOn(
			[]field.SchemaField{ApiKeyField},
			[]field.SchemaField{EmailField},
		),
	}

	// Config is the configuration schema for the connector.
	Config = field.NewConfiguration(
		[]field.SchemaField{
			AccountIdField,
			ApiKeyField,
			ApiTokenField,
			EmailField,
		},
		field.WithConnectorDisplayName("Cloudflare Zero Trust"),
		field.WithHelpUrl("/docs/baton/cloudflare-zero-trust"),
		field.WithIconUrl("/static/app-icons/cloudflare.svg"),
		field.WithConstraints(FieldRelationships...),
	)
)
