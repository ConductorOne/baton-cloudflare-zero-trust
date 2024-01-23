package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	ApiKey    string `mapstructure:"api-key"`
	AccountID string `mapstructure:"account-id"`
	Email     string `mapstructure:"email"`
	ApiToken  string `mapstructure:"api-token"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.AccountID == "" {
		return fmt.Errorf("account-id is required")
	}

	if cfg.ApiToken != "" && cfg.ApiKey != "" && cfg.Email != "" {
		return fmt.Errorf("api-token cannot be used with api-key and email")
	}

	if cfg.ApiToken == "" && cfg.ApiKey == "" && cfg.Email == "" {
		return fmt.Errorf("either api-token, or api-key and email is required")
	}

	if cfg.ApiToken != "" {
		return nil
	}

	if cfg.ApiKey == "" {
		return fmt.Errorf("api-key is required")
	}

	if cfg.Email == "" {
		return fmt.Errorf("email is required")
	}

	return nil
}

func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("api-taken", "", "Cloudflare API token ($BATON_API_TOKEN)")
	cmd.PersistentFlags().String("api-key", "", "Cloudflare API key ($BATON_API_KEY)")
	cmd.PersistentFlags().String("account-id", "", "Cloudflare account ID ($BATON_ACCOUNT_ID)")
	cmd.PersistentFlags().String("email", "", "Cloudflare account email ($BATON_EMAIL)")
}
