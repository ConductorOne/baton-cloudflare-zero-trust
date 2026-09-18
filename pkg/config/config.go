package config

import "github.com/conductorone/baton-sdk/pkg/field"

var (
	accountIdField = field.StringField(
		"account-id",
		field.WithRequired(true),
		field.WithDisplayName("Account ID"),
		field.WithDescription("Cloudflare account ID"),
	)
	apiKeyField = field.StringField(
		"api-key",
		field.WithDisplayName("API Key"),
		field.WithDescription("Cloudflare API key"),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	apiTokenField = field.StringField(
		"api-token",
		field.WithDisplayName("API Token"),
		field.WithDescription("Cloudflare API token"),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	emailField = field.StringField(
		"email",
		field.WithDisplayName("Email"),
		field.WithDescription("Cloudflare account email"),
		field.WithRequired(true),
	)
	baseURLField = field.StringField(
		"base-url",
		field.WithDescription("Override the Cloudflare API URL (for testing)"),
		field.WithHidden(true),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	configurationFields = []field.SchemaField{
		accountIdField,
		apiKeyField,
		apiTokenField,
		emailField,
		baseURLField,
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	configurationFields,
	field.WithConnectorDisplayName("Cloudflare Zero Trust"),
	field.WithHelpUrl("/docs/baton/cloudflare-zero-trust"),
	field.WithIconUrl("/static/app-icons/cloudflare-zero-trust.svg"),
	field.WithFieldGroups([]field.SchemaFieldGroup{
		{
			Name:        "api-token-group",
			DisplayName: "API Token",
			HelpText:    "Use an API token for authentication.",
			Fields:      []field.SchemaField{accountIdField, apiTokenField},
			Default:     true,
		},
		{
			Name:        "api-key-group",
			DisplayName: "Email + API key",
			HelpText:    "Use an API key with email for authentication.",
			Fields:      []field.SchemaField{accountIdField, emailField, apiKeyField},
		},
	}),
)
