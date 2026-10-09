package connector

import (
	"context"

	"github.com/conductorone/baton-cloudflare-zero-trust/pkg/client"
	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Connector struct {
	client    *client.Client
	accountId string
}

// ResourceSyncers returns a ResourceSyncerV2 for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newUserBuilder(d.client, d.accountId),
		newGroupBuilder(d.client, d.accountId),
		newRoleBuilder(d.client, d.accountId),
	}
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Cloudflare Zero Trust",
		Description: "Syncs users, groups, and roles from Cloudflare Zero Trust and provisions group and role access.",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, err := d.client.AccessKeysConfig(ctx)
	if err != nil {
		return nil, wrapError(err, "failed to validate access keys config")
	}

	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, ac *cfg.CloudflareZeroTrust, _ *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	c, err := client.New(ac.AccountId, ac.ApiToken, ac.ApiKey, ac.Email, ac.BaseUrl)
	if err != nil {
		return nil, nil, err
	}

	return &Connector{
		client:    c,
		accountId: ac.AccountId,
	}, nil, nil
}

// NewLambdaConnector returns a new instance of the connector for lambda use.
func NewLambdaConnector(ctx context.Context, ac *cfg.CloudflareZeroTrust, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	return New(ctx, ac, opts)
}
