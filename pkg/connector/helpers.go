package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
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
// roleBuilder.StaticEntitlements instead. Grants are still synced.
func annotationsForRoleResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlements{})
	annos.Update(capabilityPermissions(
		"Account Settings Read",
		"Memberships Read",
		"Memberships Write",
	))
	return annos
}

func getAccessIncludeEmails(include []interface{}) []string {
	var emailArr []string
	for _, includeRule := range include {
		im, ok := includeRule.(map[string]interface{})
		if !ok {
			continue
		}
		em, ok := im["email"].(map[string]interface{})
		if !ok {
			continue
		}
		email, ok := em["email"].(string)
		if !ok {
			continue
		}
		emailArr = append(emailArr, email)
	}
	return emailArr
}

func groupContainsUser(target string, emails []string) bool {
	for _, email := range emails {
		if target == email {
			return true
		}
	}
	return false
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

	email, err := getValueFromUserTrait(resource, "email")
	if err == nil {
		return email, nil
	}

	parts := strings.SplitN(resource.DisplayName, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("unable to get email from user trait profile")
	}
	return resource.DisplayName, nil
}
