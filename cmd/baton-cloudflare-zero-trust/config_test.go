package main

import (
	"testing"

	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/ustrings"
)

// The connector authenticates with one of two field groups: an API token, or
// an API key + account email. Each group is validated on its own via
// WithAuthMethod: selecting a group is what makes the two methods mutually
// exclusive, and every field within the selected group is required for that
// method. account-id is required by both groups.
func TestConfigs(t *testing.T) {
	t.Run("api-token group", func(t *testing.T) {
		exerciseAuthGroup(t, "api-token-group", []test.TestCaseFromExpression{
			{Expression: "", IsValid: false, Message: "empty configs"},
			{Expression: "--account-id 1", IsValid: false, Message: "missing api token"},
			{Expression: "--account-id 1 --api-token 1", IsValid: true, Message: "account id and api token"},
		})
	})

	t.Run("api-key group", func(t *testing.T) {
		exerciseAuthGroup(t, "api-key-group", []test.TestCaseFromExpression{
			{Expression: "--account-id 1", IsValid: false, Message: "missing api key and email"},
			{Expression: "--account-id 1 --api-key 1", IsValid: false, Message: "missing email"},
			{Expression: "--account-id 1 --api-key 1 --email 1", IsValid: true, Message: "account id, api key and email"},
		})
	})
}

// exerciseAuthGroup validates each expression against the config as if the
// given field group were the selected auth method.
func exerciseAuthGroup(t *testing.T, authMethod string, testCases []test.TestCaseFromExpression) {
	t.Helper()
	for _, tc := range testCases {
		t.Run(tc.Message, func(t *testing.T) {
			values, err := ustrings.ParseFlags(tc.Expression)
			if err != nil {
				t.Fatal("could not parse flags:", err)
			}

			test.AssertValidation(t, func() error {
				return field.Validate(cfg.Config, test.MakeViper(values), field.WithAuthMethod(authMethod))
			}, tc.IsValid)
		})
	}
}
