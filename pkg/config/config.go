package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var AccountIdField = field.StringField(
	"account-id",
	field.WithRequired(true),
	field.WithDescription("Cloudflare account ID"),
)
var ApiKeyField = field.StringField(
	"api-key",
	field.WithDescription("Cloudflare API key"),
)
var ApiTokenField = field.StringField(
	"api-token",
	field.WithDescription("Cloudflare API token"),
)
var EmailField = field.StringField(
	"email",
	field.WithDescription("Cloudflare account email"),
)

var configurationFields = []field.SchemaField{
	AccountIdField,
	ApiKeyField,
	ApiTokenField,
	EmailField,
}
var fieldRelationships = []field.SchemaFieldRelationship{
	field.FieldsAtLeastOneUsed(ApiTokenField, ApiKeyField),
	field.FieldsMutuallyExclusive(ApiTokenField, ApiKeyField),
	field.FieldsDependentOn(
		[]field.SchemaField{ApiKeyField},
		[]field.SchemaField{EmailField},
	),
}

//go:generate go run ./gen

var Config = field.NewConfiguration(
	configurationFields,
	field.WithConnectorDisplayName("Cloudflare Zero Trust"),
	field.WithHelpUrl("/docs/baton/cloudflare-zero-trust"),
	field.WithIconUrl("/static/app-icons/cloudflare.svg"),
	field.WithConstraints(fieldRelationships...),
)
