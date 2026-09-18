package connector

import (
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
)

// TestAccountMemberStatus pins the mapping that keeps an unaccepted invite
// from being reported as an active user. Without it the member would inherit
// NewUserTrait's enabled default.
func TestAccountMemberStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   v2.Status_ResourceStatus
	}{
		{"accepted", "accepted", v2.Status_RESOURCE_STATUS_ENABLED},
		{"pending", "pending", v2.Status_RESOURCE_STATUS_PENDING},
		{"case insensitive", "Accepted", v2.Status_RESOURCE_STATUS_ENABLED},
		{"unknown value is not guessed at", "something-else", v2.Status_RESOURCE_STATUS_UNSPECIFIED},
		{"empty", "", v2.Status_RESOURCE_STATUS_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, accountMemberStatus(tt.status))
		})
	}
}
