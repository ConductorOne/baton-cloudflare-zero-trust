package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

var (
	userResourceType = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotationsForUserResourceType(),
	}
	groupResourceType = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: annotations.New(capabilityPermissions(
			"Account Settings Read",
			"Access: Organizations, Identity Providers, and Groups Read",
			"Access: Organizations, Identity Providers, and Groups Write",
			"Memberships Read",
		)),
	}
	roleResourceType = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
		Annotations: annotations.New(capabilityPermissions(
			"Account Settings Read",
			"Memberships Read",
			"Memberships Write",
		)),
	}
)
