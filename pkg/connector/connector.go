package connector

import (
	"context"

	"github.com/cloudflare/cloudflare-go"
	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Connector struct {
	client    *cloudflare.API
	accountId string
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newUserBuilder(d.client, d.accountId),
		newGroupBuilder(d.client, d.accountId),
		newRoleBuilder(d.client, d.accountId),
		newMemberBuilder(d.client, d.accountId),
	}
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Baton Cloudflare Zero Trust",
		Description: "The template implementation of a baton connector",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (d *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, err := d.client.AccessKeysConfig(ctx, d.accountId)
	if err != nil {
		return nil, wrapError(err, "failed to validate access keys config")
	}

	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, c *cfg.CloudflareZeroTrust, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	var (
		client *cloudflare.API
		err    error
	)
	if c.ApiKey != "" && c.Email != "" {
		client, err = cloudflare.New(c.ApiKey, c.Email)
	} else if c.ApiToken != "" {
		client, err = cloudflare.NewWithAPIToken(c.ApiToken)
	}

	if err != nil {
		return nil, nil, err
	}

	return &Connector{
		client:    client,
		accountId: c.AccountId,
	}, nil, nil
}
