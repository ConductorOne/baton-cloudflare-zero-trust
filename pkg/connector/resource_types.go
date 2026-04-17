package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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
		Annotations: annotationsWithPermissions(capabilityPermissions(
			"Access: Organizations, Identity Providers, and Groups:Read",
			"Access: Organizations, Identity Providers, and Groups:Edit",
			"Account Settings:Read",
		)),
	}
	roleResourceType = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
		Annotations: annotationsWithPermissions(capabilityPermissions(
			"Account Settings:Read",
			"Account Settings:Edit",
		)),
	}
	memberResourceType = &v2.ResourceType{
		Id:          "member",
		DisplayName: "Member",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotationsWithPermissions(capabilityPermissions(
			"Account Settings:Read",
		)),
	}
)
