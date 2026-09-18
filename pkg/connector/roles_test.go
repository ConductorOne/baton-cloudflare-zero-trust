package connector

import (
	"context"
	"testing"

	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/require"
)

// TestRoleStaticEntitlementTemplate mirrors the group builder's check:
// NewAssignmentEntitlement defaults DisplayName to the slug and the SDK
// substitutes the resource's own name only when the template's is empty, so
// a constant would make every role's entitlement render identically.
func TestRoleStaticEntitlementTemplate(t *testing.T) {
	r := &roleBuilder{resourceType: roleResourceType}

	ents, _, err := r.StaticEntitlements(context.Background(), rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, ents, 1)

	require.Empty(t, ents[0].GetDisplayName(),
		"must be empty so the SDK substitutes each role's own name")
	require.NotEmpty(t, ents[0].GetDescription())
	require.Equal(t, roleAssignmentEntitlement, ents[0].GetSlug())
}
