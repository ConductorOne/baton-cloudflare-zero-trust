package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
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
	return annos
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
	trait, err := rs.GetUserTrait(resource)
	if err != nil {
		return "", err
	}

	value, ok := rs.GetProfileStringValue(trait.Profile, profileField)
	if !ok {
		return "", err
	}

	return value, nil
}

// findMemberByUserID pages through every account member looking for the one
// whose native user ID matches userId. There is no way to filter members by
// user ID server-side, so this always scans until a match or the last page.
// A nil member with a nil error means no account member has this user ID —
// e.g. the ID belongs to a pure Access user with no account membership.
func findMemberByUserID(ctx context.Context, client *cloudflare.API, accountId, userId string) (*cloudflare.AccountMember, error) {
	page := 1
	for {
		members, info, err := client.AccountMembers(ctx, accountId, cloudflare.PaginationOptions{
			Page:    page,
			PerPage: resourcePageSize,
		})
		if err != nil {
			return nil, err
		}

		for i := range members {
			if members[i].User.ID == userId {
				return &members[i], nil
			}
		}

		if info.TotalPages <= info.Page {
			return nil, nil
		}
		page++
	}
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
