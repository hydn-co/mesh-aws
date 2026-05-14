package api

import (
	"context"
	"time"

	"github.com/fgrzl/enumerators"
)

// IAMUserEnumerator returns all IAM users as an enumerator.
func (c *Client) IAMUserEnumerator(ctx context.Context) enumerators.Enumerator[IAMUser] {
	marker := ""

	return enumerators.PageItemEnumerator(func() ([]IAMUser, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IAMGroup, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IAMGroup, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IAMRole, bool, error) {
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

// IAMPolicyEnumerator returns all IAM policies as an enumerator.
func (c *Client) IAMPolicyEnumerator(ctx context.Context, scope string) enumerators.Enumerator[IAMPolicy] {
	marker := ""

	return enumerators.PageItemEnumerator(func() ([]IAMPolicy, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IAMVirtualMFADevice, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IdentityStoreUser, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IdentityStoreGroup, bool, error) {
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

	return enumerators.PageItemEnumerator(func() ([]IdentityStoreGroupMembership, bool, error) {
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

// CloudTrailEventEnumerator returns CloudTrail lookup events for a given event name and start time.
func (c *Client) CloudTrailEventEnumerator(
	ctx context.Context,
	eventName string,
	startTime *time.Time,
) enumerators.Enumerator[CloudTrailEvent] {
	nextToken := ""

	return enumerators.PageItemEnumerator(func() ([]CloudTrailEvent, bool, error) {
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
