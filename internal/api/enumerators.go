package api

import (
	"context"
	"time"

	"github.com/hydn-co/substrate/enumerators"
)

// IAMUserEnumerator returns all IAM users as an enumerator.
func (c *Client) IAMUserEnumerator(ctx context.Context) enumerators.Enumerator[IAMUser] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMUser, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		users, truncated, nextMarker, err := c.ListUsers(ctx, "", marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return users, truncated && nextMarker != "", nil
	})
}

// IAMGroupEnumerator returns all IAM groups as an enumerator.
func (c *Client) IAMGroupEnumerator(ctx context.Context) enumerators.Enumerator[IAMGroup] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMGroup, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		groups, truncated, nextMarker, err := c.ListGroups(ctx, "", marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return groups, truncated && nextMarker != "", nil
	})
}

// IAMGroupsForUserEnumerator returns all IAM groups for a user as an enumerator.
func (c *Client) IAMGroupsForUserEnumerator(ctx context.Context, userName string) enumerators.Enumerator[IAMGroup] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMGroup, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		groups, truncated, nextMarker, err := c.ListGroupsForUser(ctx, userName, marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return groups, truncated && nextMarker != "", nil
	})
}

// IAMRoleEnumerator returns all IAM roles as an enumerator.
func (c *Client) IAMRoleEnumerator(ctx context.Context) enumerators.Enumerator[IAMRole] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMRole, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		roles, truncated, nextMarker, err := c.ListRoles(ctx, "", marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return roles, truncated && nextMarker != "", nil
	})
}

// IAMAttachedRolePolicyEnumerator returns all managed policies attached to a role as an enumerator.
func (c *Client) IAMAttachedRolePolicyEnumerator(
	ctx context.Context,
	roleName string,
) enumerators.Enumerator[IAMAttachedPolicy] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMAttachedPolicy, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		policies, truncated, nextMarker, err := c.ListAttachedRolePolicies(ctx, roleName, marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return policies, truncated && nextMarker != "", nil
	})
}

// IAMInlineRolePolicyEnumerator returns all inline policy names embedded in a role as an enumerator.
func (c *Client) IAMInlineRolePolicyEnumerator(
	ctx context.Context,
	roleName string,
) enumerators.Enumerator[string] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]string, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		names, truncated, nextMarker, err := c.ListRolePolicies(ctx, roleName, marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return names, truncated && nextMarker != "", nil
	})
}

// IAMPolicyEnumerator returns all IAM policies as an enumerator.
func (c *Client) IAMPolicyEnumerator(ctx context.Context, scope string) enumerators.Enumerator[IAMPolicy] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMPolicy, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		policies, truncated, nextMarker, err := c.ListPolicies(ctx, scope, marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return policies, truncated && nextMarker != "", nil
	})
}

// IAMVirtualMFADeviceEnumerator returns all IAM virtual MFA devices as an enumerator.
func (c *Client) IAMVirtualMFADeviceEnumerator(ctx context.Context) enumerators.Enumerator[IAMVirtualMFADevice] {
	marker := ""

	return awsPageEnumerator(ctx, func() ([]IAMVirtualMFADevice, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		devices, truncated, nextMarker, err := c.ListVirtualMFADevices(ctx, marker)
		if err != nil {
			return nil, false, err
		}

		marker = nextMarker
		return devices, truncated && nextMarker != "", nil
	})
}

// IdentityStoreUserEnumerator returns all users in the given Identity Store as an enumerator.
func (c *Client) IdentityStoreUserEnumerator(
	ctx context.Context,
	identityStoreID string,
) enumerators.Enumerator[IdentityStoreUser] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]IdentityStoreUser, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		users, token, err := c.ListIdentityStoreUsers(ctx, identityStoreID, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return users, token != "", nil
	})
}

// IdentityStoreGroupEnumerator returns all groups in the given Identity Store as an enumerator.
func (c *Client) IdentityStoreGroupEnumerator(
	ctx context.Context,
	identityStoreID string,
) enumerators.Enumerator[IdentityStoreGroup] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]IdentityStoreGroup, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		groups, token, err := c.ListIdentityStoreGroups(ctx, identityStoreID, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return groups, token != "", nil
	})
}

// IdentityStoreGroupMembershipEnumerator returns all memberships for a group as an enumerator.
func (c *Client) IdentityStoreGroupMembershipEnumerator(
	ctx context.Context,
	identityStoreID, groupID string,
) enumerators.Enumerator[IdentityStoreGroupMembership] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]IdentityStoreGroupMembership, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		memberships, token, err := c.ListGroupMemberships(ctx, identityStoreID, groupID, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return memberships, token != "", nil
	})
}

// OrganizationAccountEnumerator returns all member accounts in the organization as an enumerator.
func (c *Client) OrganizationAccountEnumerator(ctx context.Context) enumerators.Enumerator[Account] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]Account, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		accounts, token, err := c.ListAccounts(ctx, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return accounts, token != "", nil
	})
}

// OrganizationAccountsForParentEnumerator returns the member accounts directly under
// the given parent (root or OU) as an enumerator.
func (c *Client) OrganizationAccountsForParentEnumerator(
	ctx context.Context,
	parentID string,
) enumerators.Enumerator[Account] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]Account, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		accounts, token, err := c.ListAccountsForParent(ctx, parentID, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return accounts, token != "", nil
	})
}

// OrganizationRootEnumerator returns the organization roots as an enumerator.
func (c *Client) OrganizationRootEnumerator(ctx context.Context) enumerators.Enumerator[OrganizationalUnit] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]OrganizationalUnit, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		roots, token, err := c.ListRoots(ctx, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return roots, token != "", nil
	})
}

// OrganizationalUnitsForParentEnumerator returns the OUs directly under the given
// parent (root or OU) as an enumerator.
func (c *Client) OrganizationalUnitsForParentEnumerator(
	ctx context.Context,
	parentID string,
) enumerators.Enumerator[OrganizationalUnit] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]OrganizationalUnit, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		ous, token, err := c.ListOrganizationalUnitsForParent(ctx, parentID, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return ous, token != "", nil
	})
}

// SecretEnumerator returns all Secrets Manager secrets (metadata only) in the
// client's region as an enumerator.
func (c *Client) SecretEnumerator(ctx context.Context) enumerators.Enumerator[Secret] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]Secret, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		secrets, token, err := c.ListSecrets(ctx, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return secrets, token != "", nil
	})
}

// TaggedResourceEnumerator returns all tagged-resource ARNs in the client's
// region as an enumerator.
func (c *Client) TaggedResourceEnumerator(ctx context.Context) enumerators.Enumerator[TaggedResource] {
	paginationToken := ""

	return awsPageEnumerator(ctx, func() ([]TaggedResource, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		resources, token, err := c.GetResources(ctx, paginationToken)
		if err != nil {
			return nil, false, err
		}

		paginationToken = token
		return resources, token != "", nil
	})
}

// CloudTrailEventEnumerator returns CloudTrail lookup events for a given event name and start time.
func (c *Client) CloudTrailEventEnumerator(
	ctx context.Context,
	eventName string,
	startTime *time.Time,
) enumerators.Enumerator[CloudTrailEvent] {
	nextToken := ""

	return awsPageEnumerator(ctx, func() ([]CloudTrailEvent, bool, error) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		events, token, err := c.LookupEvents(ctx, eventName, startTime, nextToken)
		if err != nil {
			return nil, false, err
		}

		nextToken = token
		return events, token != "", nil
	})
}
