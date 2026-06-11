package entity

import (
	"context"
	"fmt"
	"testing"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

// fakeRoleActionsClient is a configurable role-collector client that records how
// often each managed policy's actions are resolved.
type fakeRoleActionsClient struct {
	attached       map[string][]api.IAMAttachedPolicy // keyed by role name
	inline         map[string][]string                // keyed by role name
	managedActions map[string][]string                // keyed by policy ARN
	managedErrors  map[string]error                   // keyed by policy ARN
	inlineActions  map[string][]string                // keyed by roleName|policyName
	managedCalls   map[string]int                     // keyed by policy ARN
	roles          []api.IAMRole
}

func (f *fakeRoleActionsClient) IAMRoleEnumerator(_ context.Context) enumerators.Enumerator[api.IAMRole] {
	return sliceEnumerator(f.roles)
}

func (f *fakeRoleActionsClient) IAMAttachedRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[api.IAMAttachedPolicy] {
	return sliceEnumerator(f.attached[roleName])
}

func (f *fakeRoleActionsClient) IAMInlineRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[string] {
	return sliceEnumerator(f.inline[roleName])
}

func (f *fakeRoleActionsClient) IAMManagedPolicyActions(
	_ context.Context,
	policyArn string,
) ([]string, error) {
	if f.managedCalls == nil {
		f.managedCalls = map[string]int{}
	}
	f.managedCalls[policyArn]++
	if err := f.managedErrors[policyArn]; err != nil {
		return nil, err
	}
	return f.managedActions[policyArn], nil
}

func (f *fakeRoleActionsClient) IAMInlineRolePolicyActions(
	_ context.Context,
	roleName, policyName string,
) ([]string, error) {
	return f.inlineActions[roleName+"|"+policyName], nil
}

func newRoleCollectorWithClient(
	t *testing.T,
	emitter *captureEntityEmitter,
	client *fakeRoleActionsClient,
	collectInline bool,
) *AWSRoleEntityCollector {
	t.Helper()

	return &AWSRoleEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSRoleEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      contractScopeOptions(options.ModeSingle),
			CollectInlinePolicies:    collectInline,
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsRoleEntityClient, error) {
			return client, nil
		},
	}
}

func emittedPermissionsByRef(emitted []any) map[string]*entities.Permission {
	permissions := map[string]*entities.Permission{}
	for _, item := range emitted {
		if permission, ok := item.(*entities.Permission); ok {
			permissions[permission.PermissionRef] = permission
		}
	}
	return permissions
}

func emittedRolePermissionKeys(emitted []any) []string {
	keys := make([]string, 0)
	for _, item := range emitted {
		if rolePermission, ok := item.(*entities.RolePermission); ok {
			keys = append(keys, rolePermission.RoleRef+"|"+rolePermission.PermissionRef)
		}
	}
	return keys
}

func TestShouldEmitPermissionPerIAMActionWithMappedVerbWhenRoleHasPolicies(t *testing.T) {
	// Arrange
	const policyArn = "arn:aws:iam::123456789012:policy/storage-access"
	client := &fakeRoleActionsClient{
		roles: []api.IAMRole{{RoleID: "role-1", RoleName: "storage", Arn: "arn:aws:iam::123456789012:role/storage"}},
		attached: map[string][]api.IAMAttachedPolicy{
			"storage": {{PolicyName: "storage-access", PolicyArn: policyArn}},
		},
		inline:         map[string][]string{"storage": {"InlineAccess"}},
		managedActions: map[string][]string{policyArn: {"s3:DeleteObject", "s3:GetObject"}},
		inlineActions:  map[string][]string{"storage|InlineAccess": {"sqs:SendMessage"}},
	}
	emitter := &captureEntityEmitter{}
	collector := newRoleCollectorWithClient(t, emitter, client, true)

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))

	// Assert
	permissions := emittedPermissionsByRef(emitter.emitted)
	require.Len(t, permissions, 3)
	require.Equal(t, types.PermissionDelete, permissions["s3:DeleteObject"].PermissionType)
	require.Equal(t, types.PermissionRead, permissions["s3:GetObject"].PermissionType)
	require.Equal(t, types.PermissionExecute, permissions["sqs:SendMessage"].PermissionType)
	require.Equal(t, "s3:GetObject", permissions["s3:GetObject"].Name)
	require.ElementsMatch(t, []string{
		"role-1|s3:DeleteObject",
		"role-1|s3:GetObject",
		"role-1|sqs:SendMessage",
	}, emittedRolePermissionKeys(emitter.emitted))
}

func TestShouldDedupePermissionsAndCachePolicyDocumentsWhenRolesShareManagedPolicy(t *testing.T) {
	// Arrange
	const policyArn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	client := &fakeRoleActionsClient{
		roles: []api.IAMRole{
			{RoleID: "role-1", RoleName: "reader-one"},
			{RoleID: "role-2", RoleName: "reader-two"},
		},
		attached: map[string][]api.IAMAttachedPolicy{
			"reader-one": {{PolicyName: "ReadOnlyAccess", PolicyArn: policyArn}},
			"reader-two": {{PolicyName: "ReadOnlyAccess", PolicyArn: policyArn}},
		},
		managedActions: map[string][]string{policyArn: {"s3:GetObject"}},
	}
	emitter := &captureEntityEmitter{}
	collector := newRoleCollectorWithClient(t, emitter, client, false)

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))

	// Assert: one Permission, one policy-document fetch, one edge per role.
	require.Len(t, emittedPermissionsByRef(emitter.emitted), 1)
	require.Equal(t, 1, client.managedCalls[policyArn])
	require.ElementsMatch(t, []string{
		"role-1|s3:GetObject",
		"role-2|s3:GetObject",
	}, emittedRolePermissionKeys(emitter.emitted))
}

func TestShouldEmitRoleAndRemainingActionsWhenOneManagedPolicyFetchFails(t *testing.T) {
	// Arrange
	const (
		brokenArn  = "arn:aws:iam::123456789012:policy/broken"
		workingArn = "arn:aws:iam::123456789012:policy/working"
	)
	client := &fakeRoleActionsClient{
		roles: []api.IAMRole{{RoleID: "role-1", RoleName: "mixed"}},
		attached: map[string][]api.IAMAttachedPolicy{
			"mixed": {
				{PolicyName: "broken", PolicyArn: brokenArn},
				{PolicyName: "working", PolicyArn: workingArn},
			},
		},
		managedActions: map[string][]string{workingArn: {"ec2:DescribeInstances"}},
		managedErrors:  map[string]error{brokenArn: fmt.Errorf("iam AccessDenied: not authorized (HTTP 403)")},
	}
	emitter := &captureEntityEmitter{}
	collector := newRoleCollectorWithClient(t, emitter, client, false)

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))

	// Assert: the role and the working policy's actions still land.
	roles := 0
	for _, item := range emitter.emitted {
		if _, ok := item.(*entities.Role); ok {
			roles++
		}
	}
	require.Equal(t, 1, roles)
	permissions := emittedPermissionsByRef(emitter.emitted)
	require.Len(t, permissions, 1)
	require.NotNil(t, permissions["ec2:DescribeInstances"])
}
