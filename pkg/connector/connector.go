package connector

import (
	"context"

	"github.com/cloudflare/cloudflare-go"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Connector struct {
	client    *cloudflare.API
	accountId string
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (d *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newUserBuilder(d.client, d.accountId),
		newGroupBuilder(d.client, d.accountId),
	}
}

// Metadata returns metadata about the connector.
func (d *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "My Baton Connector",
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
func New(ctx context.Context, accountId, apiToken, apiKey, email string) (*Connector, error) {
	var (
		client *cloudflare.API
		err    error
	)
	if apiKey != "" && email != "" && apiToken == "" {
		client, err = cloudflare.New(apiKey, email)
	} else {
		client, err = cloudflare.NewWithAPIToken(apiToken)
	}

	if err != nil {
		return nil, err
	}

	return &Connector{
		client:    client,
		accountId: accountId,
	}, nil
}
