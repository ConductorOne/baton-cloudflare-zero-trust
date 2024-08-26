package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	accountIdField = field.StringField(
		"account-id",
		field.WithRequired(true),
		field.WithDescription("Cloudflare account ID"),
	)
	apiKeyField = field.StringField(
		"api-key",
		field.WithDescription("Cloudflare API key"),
	)
	apiTokenField = field.StringField(
		"api-token",
		field.WithDescription("Cloudflare API token"),
	)
	emailField = field.StringField(
		"email",
		field.WithDescription("Cloudflare account email"),
	)
	configurationFields = []field.SchemaField{
		accountIdField,
		apiKeyField,
		apiTokenField,
		emailField,
	}
	fieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsAtLeastOneUsed(apiTokenField, apiKeyField),
		field.FieldsDependentOn(
			[]field.SchemaField{apiKeyField},
			[]field.SchemaField{emailField},
		),
	}
)
