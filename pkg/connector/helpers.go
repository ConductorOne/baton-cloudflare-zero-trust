package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// annotationsForUserResourceType tells the SDK to skip the per-resource
// entitlements sync phase for users (userBuilder.Entitlements always returns
// nil). Grants are not skipped: userBuilder.Grants emits each user's role
// assignment grants.
func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlements{})
	annos.Update(capabilityPermissions(
		"Account Settings Read",
		"Access: Apps and Policies Read",
		"Memberships Read",
	))
	return annos
}

// capabilityPermissions declares the Cloudflare API token permission groups
// a resource type needs, surfaced in baton_capabilities.json so operators
// can see what to grant before connecting. Names match Cloudflare's API
// token permission group display names exactly.
func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

// annotationsForRoleResourceType tells the SDK to skip the per-resource
// entitlements sync phase for roles. Role entitlements are declared once via
// roleBuilder.StaticEntitlements instead. Grants are also skipped:
// roleBuilder.Grants always returns nil now that role assignment grants are
// emitted from userBuilder.Grants, so there is no reason for the SDK to
// dispatch a per-resource Grants call for any of the (often 100+) roles.
func annotationsForRoleResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlements{})
	annos.Update(&v2.SkipGrants{})
	annos.Update(capabilityPermissions(
		"Account Settings Read",
		"Memberships Read",
		"Memberships Write",
	))
	return annos
}

func getValueFromUserTrait(resource *v2.Resource, profileField string) (string, error) {
	// The profile now lives on the resource rather than the trait, but the trait
	// lookup is kept so a non-user resource is still rejected here.
	if _, err := rs.GetUserTrait(resource); err != nil {
		return "", err
	}

	value, ok := rs.GetProfileStringValue(rs.GetProfile(resource), profileField)
	if !ok {
		return "", nil
	}

	return value, nil
}

func getEmailFromUserTrait(resource *v2.Resource) (string, error) {
	trait, err := rs.GetUserTrait(resource)
	if err != nil {
		return "", err
	}

	emails := trait.GetEmails()
	for _, email := range emails {
		if email.IsPrimary {
			return email.Address, nil
		}
	}

	// An absent profile field reads as ("", nil), so the value has to be
	// checked as well as the error: returning an empty address here would let
	// a caller write an Include rule naming nobody.
	email, err := getValueFromUserTrait(resource, "email")
	if err == nil && email != "" {
		return email, nil
	}

	parts := strings.SplitN(resource.DisplayName, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("unable to get email from user trait profile")
	}
	return resource.DisplayName, nil
}
