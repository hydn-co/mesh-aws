package activity

import (
	"testing"
	"time"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
)

func TestShouldMapGroupCreatedWhenCreateGroupOccurs(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-group-create",
		EventName: "CreateGroup",
		EventTime: time.Date(2026, 5, 14, 19, 0, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{"groupName": "admins"},
		UserIdentity:      awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapGroupActivityEvent(event, detail)

	require.True(t, ok)
	group, ok := mapped.(*events.GroupCreated)
	require.True(t, ok)
	assert.Equal(t, "admins", group.Target.Ref)
	assert.Equal(t, "IAM", group.GroupType)
	assert.Equal(t, "success", group.Outcome.Result)
}

func TestShouldMapGroupMembershipAddedWhenAddUserToGroupOccurs(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-group-member-add",
		EventName: "AddUserToGroup",
		EventTime: time.Date(2026, 5, 14, 19, 1, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{"groupName": "admins", "userName": "alice"},
		UserIdentity:      awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapGroupMembershipActivityEvent(event, detail)

	require.True(t, ok)
	membership, ok := mapped.(*events.GroupMemberAdded)
	require.True(t, ok)
	assert.Equal(t, "", membership.GroupRef)
	assert.Equal(t, "admins", membership.GroupName)
	assert.Equal(t, "alice", membership.Target.Ref)
	assert.Equal(t, "", membership.MembershipType)
	assert.Equal(t, "", membership.RoleInGroup)
}

func TestShouldMapRoleLifecycleWhenPermissionSetIsCreated(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-permission-set-create",
		EventName: "CreatePermissionSet",
		EventTime: time.Date(2026, 5, 14, 19, 2, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{"permissionSetName": "finance-readonly"},
		UserIdentity:      awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapRoleActivityEvent(event, detail)

	require.True(t, ok)
	activity, ok := mapped.(*events.AdministrativeActionPerformed)
	require.True(t, ok)
	assert.Equal(t, "permission_set", activity.Category)
	assert.Contains(t, activity.Summary, "finance-readonly")
}

func TestShouldMapPermissionGrantedWhenRolePolicyIsAttached(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-role-policy-attach",
		EventName: "AttachRolePolicy",
		EventTime: time.Date(2026, 5, 14, 19, 3, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{
			"roleName":  "admins",
			"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
		},
		UserIdentity: awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapEntitlementActivityEvent(event, detail)

	require.True(t, ok)
	granted, ok := mapped.(*events.PermissionGranted)
	require.True(t, ok)
	assert.Equal(t, "admins", granted.Target.Ref)
	assert.Equal(t, "arn:aws:iam::aws:policy/AdministratorAccess", granted.PermissionRef)
	assert.Equal(t, "role", granted.PermissionScope)
	assert.False(t, granted.Privileged)
}

func TestShouldMapPolicyModifiedWhenRoleTrustPolicyChanges(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-role-trust-update",
		EventName: "UpdateAssumeRolePolicy",
		EventTime: time.Date(2026, 5, 14, 19, 4, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{"roleName": "admins"},
		UserIdentity:      awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapEntitlementActivityEvent(event, detail)

	require.True(t, ok)
	modified, ok := mapped.(*events.PolicyModified)
	require.True(t, ok)
	assert.Equal(t, "role_trust_policy", modified.PolicyType)
	assert.Equal(t, "Updated", modified.ChangeType)
}

func TestShouldMapAccountCreatedWhenCreateAccountOccurs(t *testing.T) {
	event := api.CloudTrailEvent{
		EventID:   "evt-account-create",
		EventName: "CreateAccount",
		EventTime: time.Date(2026, 5, 14, 19, 5, 0, 0, time.UTC),
		Username:  "alice",
	}
	detail := &awsCloudTrailEventDetail{
		RequestParameters: map[string]any{"accountName": "corp-prod"},
		UserIdentity:      awsCloudTrailUserIdentity{Type: "IAMUser", UserName: "alice"},
	}

	mapped, ok := mapAccountActivityEvent(event, detail)

	require.True(t, ok)
	created, ok := mapped.(*events.AccountCreated)
	require.True(t, ok)
	assert.Equal(t, "Organization", created.AccountType)
	assert.Equal(t, "corp-prod", created.Target.Ref)
	assert.Equal(t, "success", created.Outcome.Result)
}
