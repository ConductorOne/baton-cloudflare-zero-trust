package client

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// envelope is the response wrapper every Cloudflare v4 API endpoint uses.
type envelope struct {
	Success    bool            `json:"success"`
	Errors     []responseInfo  `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
}

type responseInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Message implements uhttp.ErrorResponse.
func (e *envelope) Message() string {
	msgs := make([]string, 0, len(e.Errors))
	for _, info := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d: %s", info.Code, info.Message))
	}
	if len(msgs) == 0 {
		return "no error details in response"
	}
	return strings.Join(msgs, "; ")
}

// resultInfo is the paging metadata of a list response.
type resultInfo struct {
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Total      int `json:"total_count"`
}

// AccessUser is a Zero Trust Access user.
type AccessUser struct {
	ID                  string `json:"id"`
	AccessSeat          *bool  `json:"access_seat"`
	CreatedAt           string `json:"created_at"`
	Email               string `json:"email"`
	LastSuccessfulLogin string `json:"last_successful_login"`
	Name                string `json:"name"`
}

// AccountMember is a member of the account. A member's access is expressed
// either as legacy Roles or as Policies (Domain Scoped Roles), never both.
type AccountMember struct {
	ID       string                   `json:"id"`
	Code     string                   `json:"code"`
	User     AccountMemberUserDetails `json:"user"`
	Status   string                   `json:"status"`
	Roles    []AccountRole            `json:"roles,omitempty"`
	Policies []Policy                 `json:"policies,omitempty"`
}

// AccountMemberUserDetails is the user behind an account member.
type AccountMemberUserDetails struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

// AccountRole is a classic account role.
type AccountRole struct {
	ID          string                           `json:"id"`
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	Permissions map[string]AccountRolePermission `json:"permissions"`
}

// AccountRolePermission is the read/edit pair a role grants on one area.
type AccountRolePermission struct {
	Read bool `json:"read"`
	Edit bool `json:"edit"`
}

// Policy grants the permission groups it lists on the resource groups it
// lists.
type Policy struct {
	ID               string            `json:"id"`
	PermissionGroups []PermissionGroup `json:"permission_groups"`
	ResourceGroups   []ResourceGroup   `json:"resource_groups"`
	Access           string            `json:"access"`
}

// PermissionGroup is a named set of permissions used in a Policy.
type PermissionGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Meta        map[string]string `json:"meta"`
	Permissions []Permission      `json:"permissions"`
}

// Permission is one permission inside a PermissionGroup.
type Permission struct {
	ID         string            `json:"id"`
	Key        string            `json:"key"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ResourceGroup is the set of resources a Policy applies to.
type ResourceGroup struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Meta  map[string]string `json:"meta"`
	Scope Scope             `json:"scope"`
}

// Scope selects the resources of a ResourceGroup.
type Scope struct {
	Key          string        `json:"key"`
	ScopeObjects []ScopeObject `json:"objects"`
}

// ScopeObject is one resource selector inside a Scope.
type ScopeObject struct {
	Key string `json:"key"`
}

// NewResourceGroupForAccount returns a resource group covering every resource
// in the account.
func NewResourceGroupForAccount(accountID string) ResourceGroup {
	key := fmt.Sprintf("com.cloudflare.api.account.%s", accountID)
	return ResourceGroup{
		Name: key,
		Meta: map[string]string{
			"editable": "false",
		},
		Scope: Scope{
			Key:          key,
			ScopeObjects: []ScopeObject{{Key: "*"}},
		},
	}
}

// AccessGroup is a Zero Trust Access group. Its rule lists are kept as
// decoded JSON values so that rule types this connector does not model
// survive a read-modify-write unchanged.
type AccessGroup struct {
	ID        string     `json:"id,omitempty"`
	CreatedAt *time.Time `json:"created_at"`
	Name      string     `json:"name"`

	// Include is OR: the user must satisfy one of the rules.
	Include []interface{} `json:"include"`

	// Exclude is NOT: the user must not satisfy any of the rules.
	Exclude []interface{} `json:"exclude"`

	// Require is AND: the user must satisfy all of the rules.
	Require []interface{} `json:"require"`
}

// updateAccessGroupBody is the PUT body for an Access group. Name, Include,
// Exclude and Require have no omitempty: the endpoint replaces the group, so
// each must carry the value to keep.
type updateAccessGroupBody struct {
	ID      string        `json:"id,omitempty"`
	Name    string        `json:"name"`
	Include []interface{} `json:"include"`
	Exclude []interface{} `json:"exclude"`
	Require []interface{} `json:"require"`
}
