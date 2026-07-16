// Package collectors hosts the entity emission contract tests: every entity
// collector is driven through its exported NewClient seam with a fake provider
// client, and the test asserts that only the declared entity types are emitted
// and that the emitted spaces are exactly the feature's GetSpaces().
package collectors

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	sdkentities "github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/substrate/enumerators"
	"github.com/hydn-co/substrate/json/polymorphic"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/collectors/entity"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

// captureEntityEmitter captures all emitted entities for contract assertions.
type captureEntityEmitter struct {
	emitted []any
}

func (e *captureEntityEmitter) Emit(_ context.Context, entity any) error {
	e.emitted = append(e.emitted, entity)
	return nil
}

func awsSliceEnumerator[T any](items []T) enumerators.Enumerator[T] {
	emitted := false
	return enumerators.PageItemEnumerator(func() ([]T, bool, error) {
		if emitted {
			return nil, false, nil
		}
		emitted = true
		return items, false, nil
	})
}

func newAWSContractFeatureContext[T connector.FeatureOptions](
	t *testing.T,
	emitter *captureEntityEmitter,
	featureOptions T,
) *connector.TypedFeatureContext[T, *connector.NoPayload] {
	t.Helper()

	apiKeyAndSecretCredential, err := json.Marshal(map[string]string{
		"api_key":    "access-key-id",
		"api_secret": "secret-access-key",
	})
	require.NoError(t, err)

	return connector.NewTypedFeatureContext[T, *connector.NoPayload](
		connector.NewFeatureContext(
			connector.WithConfiguration(&connector.Configuration{
				TenantID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
				ConnectorID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
				Options:     polymorphic.NewEnvelope(featureOptions),
				Credentials: map[string]json.RawMessage{
					connectorutil.DefaultCredentialName: apiKeyAndSecretCredential,
				},
			}),
			connector.WithEmitter(emitter),
		),
	)
}

// singleModeScopeOptions pins the collector to the simplest single-target mode:
// the connector's own credentials against one account, no organization fan-out.
func singleModeScopeOptions() options.AWSScopeOptionsCore {
	return options.AWSScopeOptionsCore{Mode: options.ModeSingle}
}

func assertEmittedEntityContract(t *testing.T, emitted []any, allowedTypes []any, expectedSpaces []spaces.Space) {
	t.Helper()

	allowedTypeNames := make([]string, 0, len(allowedTypes))
	allowedTypeSet := map[string]struct{}{}
	for _, item := range allowedTypes {
		typeName := reflect.TypeOf(item).String()
		allowedTypeNames = append(allowedTypeNames, typeName)
		allowedTypeSet[typeName] = struct{}{}
	}

	require.NotEmpty(t, emitted, "expected at least one emitted entity")

	observedTypeSet := map[string]struct{}{}
	observedSpaces := map[spaces.Space]struct{}{}
	for _, item := range emitted {
		typeName := reflect.TypeOf(item).String()
		if _, ok := allowedTypeSet[typeName]; !ok {
			t.Fatalf("unexpected emitted entity type %s", typeName)
		}
		observedTypeSet[typeName] = struct{}{}

		// Derive the space from the SDK's own authoritative mapping rather than a
		// parallel switch: every catalog entity declares its space via GetSpace()
		// (the same source ApplyMetadata stamps from), so this assertion stays
		// self-verifying against the SDK and drift-free.
		meshEntity, ok := item.(sdkentities.MeshEntity)
		require.Truef(t, ok, "emitted %s does not implement entities.MeshEntity", typeName)
		observedSpaces[meshEntity.GetSpace()] = struct{}{}
	}

	observedTypeNames := make([]string, 0, len(observedTypeSet))
	for typeName := range observedTypeSet {
		observedTypeNames = append(observedTypeNames, typeName)
	}

	observedSpaceList := make([]spaces.Space, 0, len(observedSpaces))
	for space := range observedSpaces {
		observedSpaceList = append(observedSpaceList, space)
	}

	require.ElementsMatch(t, allowedTypeNames, observedTypeNames)
	require.ElementsMatch(t, expectedSpaces, observedSpaceList)
}

// fakeAccountEntityClient exercises every account-collector branch: IAM users
// with group memberships, Identity Store users/groups/memberships, a
// service-principal role, a human-assumable role (AccountRole edge), and the
// management account.
type fakeAccountEntityClient struct{}

func (fakeAccountEntityClient) IAMUserEnumerator(_ context.Context) enumerators.Enumerator[api.IAMUser] {
	return awsSliceEnumerator([]api.IAMUser{{
		UserID:     "iam-user-1",
		UserName:   "alice",
		Arn:        "arn:aws:iam::123456789012:user/alice",
		CreateDate: time.Date(2026, 5, 14, 18, 0, 0, 0, time.UTC),
	}})
}

func (fakeAccountEntityClient) IAMGroupsForUserEnumerator(
	_ context.Context,
	userName string,
) enumerators.Enumerator[api.IAMGroup] {
	if userName == "" {
		panic("unexpected empty IAM user name")
	}
	return awsSliceEnumerator([]api.IAMGroup{{
		GroupID:    "iam-group-1",
		GroupName:  "admins",
		Arn:        "arn:aws:iam::123456789012:group/admins",
		CreateDate: time.Date(2026, 5, 14, 18, 1, 0, 0, time.UTC),
	}})
}

func (fakeAccountEntityClient) IAMRoleEnumerator(_ context.Context) enumerators.Enumerator[api.IAMRole] {
	return awsSliceEnumerator([]api.IAMRole{{
		RoleID:            "role-1",
		RoleName:          "service-role",
		Arn:               "arn:aws:iam::123456789012:role/service-role",
		Description:       "Service role",
		ServicePrincipals: []string{"lambda.amazonaws.com"},
	}, {
		RoleID:        "role-2",
		RoleName:      "human-assumable",
		Arn:           "arn:aws:iam::123456789012:role/human-assumable",
		Description:   "Human assumable role",
		AWSPrincipals: []string{"arn:aws:iam::123456789012:user/alice"},
	}})
}

func (fakeAccountEntityClient) IdentityStoreUserEnumerator(
	_ context.Context,
	identityStoreID string,
) enumerators.Enumerator[api.IdentityStoreUser] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	return awsSliceEnumerator([]api.IdentityStoreUser{{
		UserID:      "idstore-user-1",
		UserName:    "bob@example.com",
		DisplayName: "Bob Example",
		GivenName:   "Bob",
		FamilyName:  "Example",
		Active:      true,
		CreatedAt:   time.Date(2026, 5, 14, 18, 2, 0, 0, time.UTC),
	}})
}

func (fakeAccountEntityClient) IdentityStoreGroupEnumerator(
	_ context.Context,
	identityStoreID string,
) enumerators.Enumerator[api.IdentityStoreGroup] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	return awsSliceEnumerator([]api.IdentityStoreGroup{{
		GroupID:     "idstore-group-1",
		DisplayName: "Identity Store Admins",
		Description: "Admins in identity store",
		CreatedAt:   time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC),
	}})
}

func (fakeAccountEntityClient) IdentityStoreGroupMembershipEnumerator(
	_ context.Context,
	identityStoreID, groupID string,
) enumerators.Enumerator[api.IdentityStoreGroupMembership] {
	if identityStoreID == "" || groupID == "" {
		panic("unexpected empty identity store id or group id")
	}
	return awsSliceEnumerator([]api.IdentityStoreGroupMembership{{
		MembershipID: "membership-1",
		GroupID:      groupID,
		MemberUserID: "idstore-user-1",
		CreatedAt:    time.Date(2026, 5, 14, 18, 4, 0, 0, time.UTC),
	}})
}

func (fakeAccountEntityClient) DescribeOrganization(_ context.Context) (*api.Organization, error) {
	return &api.Organization{
		MasterAccountID:    "123456789012",
		MasterAccountArn:   "arn:aws:organizations::123456789012:account/o-example/123456789012",
		MasterAccountEmail: "root@example.com",
	}, nil
}

func (fakeAccountEntityClient) ListAccessKeys(_ context.Context, userName string) ([]api.IAMAccessKey, error) {
	if userName == "alice" {
		return []api.IAMAccessKey{{
			AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
			Status:      "Active",
		}}, nil
	}
	return []api.IAMAccessKey{}, nil
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenAccountCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSAccountEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSAccountEntityCollectorOptions{
			AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:         singleModeScopeOptions(),
			AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSAccountEntityClient, error) {
			return fakeAccountEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Account{},
		&sdkentities.GroupMember{},
		&sdkentities.AccountRole{},
	}, (&options.AWSAccountEntityCollectorOptions{}).GetSpaces())
}

// fakeGroupEntityClient serves one IAM group and one Identity Store group.
type fakeGroupEntityClient struct{}

func (fakeGroupEntityClient) IAMGroupEnumerator(_ context.Context) enumerators.Enumerator[api.IAMGroup] {
	return awsSliceEnumerator([]api.IAMGroup{{
		GroupID:    "iam-group-1",
		GroupName:  "admins",
		Arn:        "arn:aws:iam::123456789012:group/admins",
		CreateDate: time.Date(2026, 5, 14, 18, 1, 0, 0, time.UTC),
	}})
}

func (fakeGroupEntityClient) IdentityStoreGroupEnumerator(
	_ context.Context,
	identityStoreID string,
) enumerators.Enumerator[api.IdentityStoreGroup] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	return awsSliceEnumerator([]api.IdentityStoreGroup{{
		GroupID:     "idstore-group-1",
		DisplayName: "Identity Store Admins",
		Description: "Admins in identity store",
		CreatedAt:   time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC),
	}})
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenGroupCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSGroupEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSGroupEntityCollectorOptions{
			AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:         singleModeScopeOptions(),
			AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSGroupEntityClient, error) {
			return fakeGroupEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Group{},
	}, (&options.AWSGroupEntityCollectorOptions{}).GetSpaces())
}

// fakeRoleEntityClient serves one role with a managed and an inline policy so
// the collector emits roles, permissions, and role-permission edges.
type fakeRoleEntityClient struct{}

func (fakeRoleEntityClient) IAMRoleEnumerator(_ context.Context) enumerators.Enumerator[api.IAMRole] {
	return awsSliceEnumerator([]api.IAMRole{{
		RoleID:      "role-1",
		RoleName:    "storage",
		Arn:         "arn:aws:iam::123456789012:role/storage",
		Description: "Storage role",
	}})
}

func (fakeRoleEntityClient) IAMAttachedRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[api.IAMAttachedPolicy] {
	if roleName == "" {
		panic("unexpected empty role name")
	}
	return awsSliceEnumerator([]api.IAMAttachedPolicy{{
		PolicyName: "AdministratorAccess",
		PolicyArn:  "arn:aws:iam::aws:policy/AdministratorAccess",
	}})
}

func (fakeRoleEntityClient) IAMInlineRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[string] {
	if roleName == "" {
		panic("unexpected empty role name")
	}
	return awsSliceEnumerator([]string{"InlineAccess"})
}

func (fakeRoleEntityClient) IAMManagedPolicyActions(_ context.Context, policyArn string) ([]string, error) {
	if policyArn == "" {
		panic("unexpected empty policy arn")
	}
	return []string{"iam:GetRole", "s3:GetObject"}, nil
}

func (fakeRoleEntityClient) IAMInlineRolePolicyActions(
	_ context.Context,
	roleName, policyName string,
) ([]string, error) {
	if roleName == "" || policyName == "" {
		panic("unexpected empty role or policy name")
	}
	return []string{"s3:PutObject"}, nil
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenRoleCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSRoleEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSRoleEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      singleModeScopeOptions(),
			CollectInlinePolicies:    true,
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSRoleEntityClient, error) {
			return fakeRoleEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Role{},
		&sdkentities.Permission{},
		&sdkentities.RolePermission{},
	}, (&options.AWSRoleEntityCollectorOptions{}).GetSpaces())
}

// fakeResourceInventoryClient serves the caller identity and one tagged
// resource per target.
type fakeResourceInventoryClient struct{}

func (fakeResourceInventoryClient) GetCallerIdentity(_ context.Context) (string, error) {
	return "123456789012", nil
}

func (fakeResourceInventoryClient) TaggedResourceEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.TaggedResource] {
	return awsSliceEnumerator([]api.TaggedResource{{
		ARN:  "arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123",
		Tags: map[string]string{"Name": "web-server"},
	}, {
		ARN: "arn:aws:s3:::contract-bucket",
	}})
}

// fakeResourceOrgTreeClient backs the resource collector's organization-tree
// walk with a root holding the management account and one OU holding the
// member account, so container-nesting edges are exercised.
type fakeResourceOrgTreeClient struct{}

func (fakeResourceOrgTreeClient) OrganizationRootEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.OrganizationalUnit] {
	return awsSliceEnumerator([]api.OrganizationalUnit{{ID: "r-1", Name: "Root"}})
}

func (fakeResourceOrgTreeClient) OrganizationalUnitsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.OrganizationalUnit] {
	if parentID == "r-1" {
		return awsSliceEnumerator([]api.OrganizationalUnit{{ID: "ou-1", Name: "Workloads"}})
	}
	return awsSliceEnumerator([]api.OrganizationalUnit{})
}

func (fakeResourceOrgTreeClient) OrganizationAccountsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.Account] {
	switch parentID {
	case "r-1":
		return awsSliceEnumerator([]api.Account{{
			ID:     "123456789012",
			Name:   "management",
			Status: api.AccountStatusActive,
		}})
	case "ou-1":
		return awsSliceEnumerator([]api.Account{{
			ID:     "210987654321",
			Name:   "member",
			Status: api.AccountStatusActive,
		}})
	default:
		return awsSliceEnumerator([]api.Account{})
	}
}

// fakeScopeOrgClient backs the resolver's organization-mode fan-out with a
// two-account organization; the member account is reached via AssumeRole.
type fakeScopeOrgClient struct{}

func (fakeScopeOrgClient) DescribeOrganization(_ context.Context) (*api.Organization, error) {
	return &api.Organization{
		MasterAccountID:    "123456789012",
		MasterAccountArn:   "arn:aws:organizations::123456789012:account/o-example/123456789012",
		MasterAccountEmail: "root@example.com",
	}, nil
}

func (fakeScopeOrgClient) OrganizationAccountEnumerator(_ context.Context) enumerators.Enumerator[api.Account] {
	return awsSliceEnumerator([]api.Account{{
		ID:     "123456789012",
		Name:   "management",
		Status: api.AccountStatusActive,
	}, {
		ID:     "210987654321",
		Name:   "member",
		Status: api.AccountStatusActive,
	}})
}

func (fakeScopeOrgClient) OrganizationAccountsForParentEnumerator(
	_ context.Context,
	_ string,
) enumerators.Enumerator[api.Account] {
	panic("unexpected OU account enumeration without configured organizational unit IDs")
}

func (fakeScopeOrgClient) OrganizationalUnitsForParentEnumerator(
	_ context.Context,
	_ string,
) enumerators.Enumerator[api.OrganizationalUnit] {
	panic("unexpected OU enumeration without configured organizational unit IDs")
}

func (fakeScopeOrgClient) AssumeRole(
	_ context.Context,
	roleArn, _, _ string,
) (*api.AssumedCredentials, error) {
	if roleArn != "arn:aws:iam::210987654321:role/HyddenDiscoveryRole" {
		panic("unexpected assume role arn: " + roleArn)
	}
	return &api.AssumedCredentials{
		AccessKeyID:     "assumed-access-key-id",
		SecretAccessKey: "assumed-secret-access-key",
		SessionToken:    "assumed-session-token",
	}, nil
}

// The resource collector is the one contract test that runs in organization
// mode: its ResourceContainerResourceContainer space (OU/account nesting) is
// only emitted while walking the Organizations tree, so single mode could not
// exercise every declared space.
func TestShouldOnlyEmitDeclaredEntityTypesWhenResourceCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSResourceEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSResourceEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore: options.AWSScopeOptionsCore{
				Mode:           options.ModeOrganization,
				AssumeRoleName: "HyddenDiscoveryRole",
			},
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSResourceEntityClient, error) {
			return fakeResourceInventoryClient{}, nil
		},
		NewOrgClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSResourceOrgClient, error) {
			return fakeResourceOrgTreeClient{}, nil
		},
		ResolverOpts: []scope.Option{
			scope.WithOrgClientFactory(func(_ *api.AWSCredentials, _, _ string) (scope.OrgClient, error) {
				return fakeScopeOrgClient{}, nil
			}),
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Resource{},
		&sdkentities.ResourceContainer{},
		&sdkentities.ResourceContainerResource{},
		&sdkentities.ResourceContainerResourceContainer{},
	}, (&options.AWSResourceEntityCollectorOptions{}).GetSpaces())
}

// fakePolicyEntityClient serves one IAM managed policy.
type fakePolicyEntityClient struct{}

func (fakePolicyEntityClient) IAMPolicyEnumerator(
	_ context.Context,
	policyScope string,
) enumerators.Enumerator[api.IAMPolicy] {
	if policyScope == "" {
		panic("unexpected empty policy scope")
	}
	return awsSliceEnumerator([]api.IAMPolicy{{
		PolicyID:    "policy-1",
		PolicyName:  "AdministratorAccess",
		Description: "Full access to AWS services",
	}})
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenPolicyCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSPolicyEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSPolicyEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      singleModeScopeOptions(),
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSPolicyEntityClient, error) {
			return fakePolicyEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Policy{},
	}, (&options.AWSPolicyEntityCollectorOptions{}).GetSpaces())
}

// fakeMFAEntityClient serves one assigned virtual MFA device (yielding an
// account link) and one unassigned device (device only).
type fakeMFAEntityClient struct{}

func (fakeMFAEntityClient) IAMVirtualMFADeviceEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.IAMVirtualMFADevice] {
	return awsSliceEnumerator([]api.IAMVirtualMFADevice{{
		SerialNumber: "arn:aws:iam::123456789012:mfa/alice",
		EnableDate:   time.Date(2026, 5, 14, 18, 5, 0, 0, time.UTC),
		UserID:       "iam-user-1",
		UserName:     "alice",
	}, {
		SerialNumber: "arn:aws:iam::123456789012:mfa/bob",
		EnableDate:   time.Date(2026, 5, 14, 18, 6, 0, 0, time.UTC),
		UserID:       "",
		UserName:     "bob",
	}})
}

func (fakeMFAEntityClient) IAMUserEnumerator(_ context.Context) enumerators.Enumerator[api.IAMUser] {
	return awsSliceEnumerator([]api.IAMUser{{
		UserID:     "iam-user-1",
		UserName:   "alice",
		Arn:        "arn:aws:iam::123456789012:user/alice",
		CreateDate: time.Date(2026, 5, 14, 18, 0, 0, 0, time.UTC),
	}})
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenMFACollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSMFAEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSMFAEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      singleModeScopeOptions(),
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSMFAEntityClient, error) {
			return fakeMFAEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.MultiFactor{},
		&sdkentities.AccountMultiFactor{},
	}, (&options.AWSMFAEntityCollectorOptions{}).GetSpaces())
}

// fakeSecretEntityClient serves one Secrets Manager secret's metadata.
type fakeSecretEntityClient struct{}

func (fakeSecretEntityClient) SecretEnumerator(_ context.Context) enumerators.Enumerator[api.Secret] {
	return awsSliceEnumerator([]api.Secret{{
		ARN:             "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/db-abc123",
		Name:            "prod/db",
		RotationEnabled: true,
	}})
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenSecretCollectorRunsWithInjectedClient(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := &entity.AWSSecretEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSSecretEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      singleModeScopeOptions(),
		}),
		NewClient: func(_ *api.AWSCredentials, _, _ string) (entity.AWSSecretEntityClient, error) {
			return fakeSecretEntityClient{}, nil
		},
	}

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	// Assert
	assertEmittedEntityContract(t, emitter.emitted, []any{
		&sdkentities.Secret{},
	}, (&options.AWSSecretEntityCollectorOptions{}).GetSpaces())
}
