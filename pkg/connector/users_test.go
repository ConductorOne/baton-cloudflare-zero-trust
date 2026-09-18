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
		wantOK bool
	}{
		{"accepted", "accepted", v2.Status_RESOURCE_STATUS_ENABLED, true},
		{"pending", "pending", v2.Status_RESOURCE_STATUS_PENDING, true},
		{"case insensitive", "Accepted", v2.Status_RESOURCE_STATUS_ENABLED, true},
		// An unrecognized value must report false, not the unspecified
		// status: the caller omits the option entirely in that case, because
		// setting unspecified would still count as setting a status and would
		// stop the trait's default reaching the resource.
		{"unknown value is not guessed at", "something-else", v2.Status_RESOURCE_STATUS_UNSPECIFIED, false},
		{"empty", "", v2.Status_RESOURCE_STATUS_UNSPECIFIED, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := accountMemberStatus(tt.status)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.want, got)
		})
	}
}
