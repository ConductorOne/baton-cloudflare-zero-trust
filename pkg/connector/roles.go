package connector

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	"github.com/conductorone/baton-cloudflare-zero-trust/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       *client.Client
	accountId    string
}

// roleAssignmentEntitlement is the slug of the single assignment entitlement
// declared for every role resource. It must stay in sync with the slug used
// when constructing grants in Grants().
const roleAssignmentEntitlement = "assigned"

var (
	ErrMissingAccountID = client.ErrMissingAccountID
	ErrMissingMemberID  = client.ErrMissingMemberID
)

func (r *roleBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// getRoleResource creates a new connector resource for a cloudflare role.
func getRoleResource(ctx context.Context, role cloudflare.AccountRole, resourceTypeRole *v2.ResourceType, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_id":   role.ID,
		"role_name": role.Name,
	}

	ret, err := rs.NewRoleResource(
		role.Name,
		resourceTypeRole,
		role.ID,
		nil,
		rs.WithParentResourceID(parentResourceID),
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// List returns all the roles from the database as resource objects.
// Roles include a RoleTrait because they are the 'shape' of a standard role.
func (r *roleBuilder) List(ctx context.Context, parentId *v2.ResourceId, _ rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	roles, annos, err := r.client.ListAccountRoles(ctx)
	if err != nil {
		return nil, nil, wrapError(err, "failed to list roles")
	}

	resources := make([]*v2.Resource, 0, len(roles))
	for _, role := range roles {
		resource, err := getRoleResource(ctx, *role, roleResourceType, parentId)
		if err != nil {
			return nil, nil, wrapError(err, "failed to create role resource")
		}

		resources = append(resources, resource)
	}

	return resources, &rs.SyncOpResults{Annotations: annos}, nil
}

// Entitlements returns nil. Role entitlements are declared statically via
// StaticEntitlements, and the role resource type is annotated with
// SkipEntitlements, so the SDK never invokes this per-resource hook.
func (r *roleBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (r *roleBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	// DisplayName is cleared so the SDK names each entitlement after its own
	// role; a constant would render all of Cloudflare's roles identically.
	assignment := ent.NewAssignmentEntitlement(nil, roleAssignmentEntitlement,
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(""),
		ent.WithDescription("Assigned to the Cloudflare role"),
	)

	return []*v2.Entitlement{assignment}, nil, nil
}

// Grants always returns nil. Role assignment grants are emitted from
// userBuilder.Grants instead: Cloudflare has no way to list "members with
// role X" directly, so computing grants role-by-role here would mean
// re-fetching and re-scanning the entire member list once per role (and
// Cloudflare ships 100+ built-in roles that most tenants never assign).
// userBuilder.Grants instead reads role IDs that were captured once, per
// member, while userBuilder.List paginates the member list for the merged
// user sync — no extra API calls at all.
func (r *roleBuilder) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	var (
		err    error
		userId = principal.Id.Resource
	)
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"baton-cloudflare: only users can be granted role membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("baton-cloudflare: only users can be granted role membership")
	}

	memberId, err := getMemberId(ctx, r, userId)
	if err != nil {
		return nil, err
	}

	account, _, err := r.client.AccountMember(ctx, memberId)
	if err != nil {
		return nil, err
	}

	roleId := entitlement.Resource.Id.Resource

	// A member with any existing Policies is on the Domain Scoped Roles
	// model; grant via an equivalent Policy instead of the legacy Roles
	// list, which Cloudflare rejects once Policies are present.
	if len(account.Policies) > 0 {
		group, _, err := r.client.RolePermissionGroup(ctx, roleId)
		if err != nil {
			return nil, err
		}

		newPolicy := cloudflare.Policy{
			PermissionGroups: []cloudflare.PermissionGroup{{ID: group.ID}},
			ResourceGroups:   []cloudflare.ResourceGroup{cloudflare.NewResourceGroupForAccount(cloudflare.Account{ID: r.accountId})},
			Access:           "allow",
		}

		member, _, err := r.client.UpdateAccountMember(ctx, memberId, cloudflare.AccountMember{
			Policies: append(account.Policies, newPolicy),
		})
		if err != nil {
			return nil, err
		}

		l.Debug("Role has been created.",
			zap.String("ID", member.ID),
			zap.String("Status", member.Status),
		)

		return nil, nil
	}

	roles := []cloudflare.AccountRole{{ID: roleId}}
	for _, role := range account.Roles {
		roles = append(roles, cloudflare.AccountRole{
			ID: role.ID,
		})
	}

	member, _, err := r.client.UpdateAccountMember(ctx, memberId, cloudflare.AccountMember{
		Roles: roles,
	})
	if err != nil {
		return nil, err
	}

	l.Debug("Role has been created.",
		zap.String("ID", member.ID),
		zap.String("Status", member.Status),
	)

	return nil, nil
}

func getMemberId(ctx context.Context, r *roleBuilder, userId string) (string, error) {
	member, err := findMemberByUserID(ctx, r.client, userId)
	if err != nil {
		return "", wrapError(err, "failed to list user members")
	}
	if member == nil {
		return "", status.Errorf(
			codes.NotFound,
			"no Cloudflare account member has user ID %q; role assignment requires account membership",
			userId,
		)
	}

	return member.ID, nil
}

func (r *roleBuilder) Revoke(ctx context.Context, grantToRevoke *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grantToRevoke.Entitlement
	principal := grantToRevoke.Principal

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"couldflare-connector: only users can have role membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("couldflare-connector: only users can have role membership revoked")
	}

	userId := principal.Id.Resource
	roleId := entitlement.Resource.Id.Resource

	memberId, err := getMemberId(ctx, r, userId)
	if err != nil {
		return nil, err
	}

	account, _, err := r.client.AccountMember(ctx, memberId)
	if err != nil {
		return nil, err
	}

	// See Grant: a member with any existing Policies is on the Domain
	// Scoped Roles model, so revoke by removing the equivalent Policy
	// instead of filtering the legacy Roles list.
	if len(account.Policies) > 0 {
		group, _, err := r.client.RolePermissionGroup(ctx, roleId)
		if err != nil {
			return nil, err
		}

		// Strip only the matching permission group from each policy - a
		// policy can bundle multiple permission groups together, and
		// dropping the whole policy would revoke unrelated grants it also
		// carries. Only drop a policy if removing the group leaves it with
		// no permission groups at all.
		policies := make([]cloudflare.Policy, 0, len(account.Policies))
		for _, policy := range account.Policies {
			remaining := make([]cloudflare.PermissionGroup, 0, len(policy.PermissionGroups))
			for _, pg := range policy.PermissionGroups {
				if pg.ID == group.ID {
					continue
				}
				remaining = append(remaining, pg)
			}
			if len(remaining) == 0 {
				continue
			}
			policy.PermissionGroups = remaining
			policies = append(policies, policy)
		}

		member, _, err := r.client.UpdateAccountMember(ctx, memberId, cloudflare.AccountMember{
			Policies: policies,
		})
		if err != nil {
			return nil, err
		}

		l.Debug("Role has been revoked.",
			zap.String("ID", member.ID),
			zap.String("Status", member.Status),
		)

		return nil, nil
	}

	roles := []cloudflare.AccountRole{}
	for _, role := range account.Roles {
		if roleId != role.ID {
			roles = append(roles, cloudflare.AccountRole{
				ID: role.ID,
			})
		}
	}

	member, _, err := r.client.UpdateAccountMember(ctx, memberId, cloudflare.AccountMember{
		Roles: roles,
	})
	if err != nil {
		return nil, err
	}

	l.Debug("Role has been revoked.",
		zap.String("ID", member.ID),
		zap.String("Status", member.Status),
	)

	return nil, nil
}

func newRoleBuilder(c *client.Client, accountId string) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       c,
		accountId:    accountId,
	}
}
