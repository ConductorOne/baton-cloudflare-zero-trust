package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

func getAccessIncludeEmails(ctx context.Context, include []interface{}) []string {
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
