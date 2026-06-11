package entity

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/fgrzl/enumerators"
	"github.com/fgrzl/json/polymorphic"
	"github.com/google/uuid"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

type captureEntityEmitter struct {
	emitted []any
}

func (e *captureEntityEmitter) Emit(_ context.Context, entity any) error {
	e.emitted = append(e.emitted, entity)
	return nil
}

type fakeAWSContractClient struct{}

func (fakeAWSContractClient) IAMUserEnumerator(_ context.Context) enumerators.Enumerator[api.IAMUser] {
	return sliceEnumerator([]api.IAMUser{{
		UserID:     "iam-user-1",
		UserName:   "alice",
		Arn:        "arn:aws:iam::123456789012:user/alice",
		CreateDate: time.Date(2026, 5, 14, 18, 0, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) IAMGroupsForUserEnumerator(
	_ context.Context,
	userName string,
) enumerators.Enumerator[api.IAMGroup] {
	if userName == "" {
		panic("unexpected empty IAM user name")
	}
	return sliceEnumerator([]api.IAMGroup{{
		GroupID:    "iam-group-1",
		GroupName:  "admins",
		Arn:        "arn:aws:iam::123456789012:group/admins",
		CreateDate: time.Date(2026, 5, 14, 18, 1, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) IdentityStoreUserEnumerator(
	_ context.Context,
	identityStoreID string,
) enumerators.Enumerator[api.IdentityStoreUser] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	return sliceEnumerator([]api.IdentityStoreUser{{
		UserID:      "idstore-user-1",
		UserName:    "bob@example.com",
		DisplayName: "Bob Example",
		GivenName:   "Bob",
		FamilyName:  "Example",
		Active:      true,
		CreatedAt:   time.Date(2026, 5, 14, 18, 2, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) IdentityStoreGroupEnumerator(
	_ context.Context,
	identityStoreID string,
) enumerators.Enumerator[api.IdentityStoreGroup] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	return sliceEnumerator([]api.IdentityStoreGroup{{
		GroupID:     "idstore-group-1",
		DisplayName: "Identity Store Admins",
		Description: "Admins in identity store",
		CreatedAt:   time.Date(2026, 5, 14, 18, 3, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) IdentityStoreGroupMembershipEnumerator(
	_ context.Context,
	identityStoreID, groupID string,
) enumerators.Enumerator[api.IdentityStoreGroupMembership] {
	if identityStoreID == "" {
		panic("unexpected empty identity store id")
	}
	if groupID == "" {
		panic("unexpected empty identity store group id")
	}
	return sliceEnumerator([]api.IdentityStoreGroupMembership{{
		MembershipID: "membership-1",
		GroupID:      groupID,
		MemberUserID: "idstore-user-1",
		CreatedAt:    time.Date(2026, 5, 14, 18, 4, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) DescribeOrganization(_ context.Context) (*api.Organization, error) {
	return &api.Organization{
		MasterAccountID:    "123456789012",
		MasterAccountArn:   "arn:aws:organizations::123456789012:account/o-example/123456789012",
		MasterAccountEmail: "root@example.com",
	}, nil
}

func (fakeAWSContractClient) ListAccessKeys(_ context.Context, userName string) ([]api.IAMAccessKey, error) {
	if userName == "alice" {
		return []api.IAMAccessKey{{
			AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
			Status:      "Active",
		}}, nil
	}
	return []api.IAMAccessKey{}, nil
}

func (fakeAWSContractClient) IAMGroupEnumerator(_ context.Context) enumerators.Enumerator[api.IAMGroup] {
	return sliceEnumerator([]api.IAMGroup{{
		GroupID:    "iam-group-1",
		GroupName:  "admins",
		Arn:        "arn:aws:iam::123456789012:group/admins",
		CreateDate: time.Date(2026, 5, 14, 18, 1, 0, 0, time.UTC),
	}})
}

func (fakeAWSContractClient) IAMRoleEnumerator(_ context.Context) enumerators.Enumerator[api.IAMRole] {
	return sliceEnumerator([]api.IAMRole{{
		RoleID:            "role-1",
		RoleName:          "admins",
		Arn:               "arn:aws:iam::123456789012:role/admins",
		Description:       "Admins role",
		ServicePrincipals: []string{"lambda.amazonaws.com"},
	}, {
		RoleID:        "role-2",
		RoleName:      "human-assumable",
		Arn:           "arn:aws:iam::123456789012:role/human-assumable",
		Description:   "Human assumable role",
		AWSPrincipals: []string{"arn:aws:iam::123456789012:user/alice"},
	}})
}

func (fakeAWSContractClient) IAMAttachedRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[api.IAMAttachedPolicy] {
	if roleName == "" {
		panic("unexpected empty role name")
	}
	return sliceEnumerator([]api.IAMAttachedPolicy{{
		PolicyName: "AdministratorAccess",
		PolicyArn:  "arn:aws:iam::aws:policy/AdministratorAccess",
	}})
}

func (fakeAWSContractClient) IAMInlineRolePolicyEnumerator(
	_ context.Context,
	roleName string,
) enumerators.Enumerator[string] {
	if roleName == "" {
		panic("unexpected empty role name")
	}
	return sliceEnumerator([]string{"InlineAccess"})
}

func (fakeAWSContractClient) IAMManagedPolicyActions(
	_ context.Context,
	policyArn string,
) ([]string, error) {
	if policyArn == "" {
		panic("unexpected empty policy arn")
	}
	return []string{"iam:GetRole", "s3:*"}, nil
}

func (fakeAWSContractClient) IAMInlineRolePolicyActions(
	_ context.Context,
	roleName, policyName string,
) ([]string, error) {
	if roleName == "" {
		panic("unexpected empty role name")
	}
	if policyName == "" {
		panic("unexpected empty policy name")
	}
	return []string{"s3:PutObject"}, nil
}

func (fakeAWSContractClient) GetCallerIdentity(_ context.Context) (string, error) {
	return "123456789012", nil
}

func (fakeAWSContractClient) TaggedResourceEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.TaggedResource] {
	return sliceEnumerator([]api.TaggedResource{{
		ARN: "arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123",
	}, {
		ARN: "arn:aws:s3:::contract-bucket",
	}})
}

func (fakeAWSContractClient) IAMPolicyEnumerator(
	_ context.Context,
	scope string,
) enumerators.Enumerator[api.IAMPolicy] {
	if scope == "" {
		panic("unexpected empty policy scope")
	}
	return sliceEnumerator([]api.IAMPolicy{{
		PolicyID:    "policy-1",
		PolicyName:  "AdministratorAccess",
		Description: "Full access to AWS services",
	}})
}

func (fakeAWSContractClient) IAMVirtualMFADeviceEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.IAMVirtualMFADevice] {
	return sliceEnumerator([]api.IAMVirtualMFADevice{{
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

// fakeOrgClient backs the resolver in organization mode with a two-account
// organization: the management account (collected with management credentials)
// and one member account reached via AssumeRole.
type fakeOrgClient struct{}

func (fakeOrgClient) DescribeOrganization(_ context.Context) (*api.Organization, error) {
	return &api.Organization{
		MasterAccountID:    "123456789012",
		MasterAccountArn:   "arn:aws:organizations::123456789012:account/o-example/123456789012",
		MasterAccountEmail: "root@example.com",
	}, nil
}

func (fakeOrgClient) OrganizationAccountEnumerator(_ context.Context) enumerators.Enumerator[api.Account] {
	return sliceEnumerator([]api.Account{{
		ID:     "123456789012",
		Name:   "management",
		Status: api.AccountStatusActive,
	}, {
		ID:     "210987654321",
		Name:   "member",
		Status: api.AccountStatusActive,
	}})
}

func (fakeOrgClient) OrganizationAccountsForParentEnumerator(
	_ context.Context,
	_ string,
) enumerators.Enumerator[api.Account] {
	panic("unexpected OU account enumeration without configured organizational unit IDs")
}

func (fakeOrgClient) OrganizationalUnitsForParentEnumerator(
	_ context.Context,
	_ string,
) enumerators.Enumerator[api.OrganizationalUnit] {
	panic("unexpected OU enumeration without configured organizational unit IDs")
}

func (fakeOrgClient) AssumeRole(
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

// contractModes are the collection modes every entity collector contract test runs under.
var contractModes = []string{options.ModeSingle, options.ModeOrganization}

func contractScopeOptions(mode string) options.AWSScopeOptionsCore {
	scopeOpts := options.AWSScopeOptionsCore{Mode: mode}
	if mode == options.ModeOrganization {
		scopeOpts.AssumeRoleName = "HyddenDiscoveryRole"
	}
	return scopeOpts
}

func contractResolverOpts() []scope.Option {
	return []scope.Option{
		scope.WithOrgClientFactory(func(_ *api.AWSCredentials, _, _ string) (scope.OrgClient, error) {
			return fakeOrgClient{}, nil
		}),
	}
}

func sliceEnumerator[T any](items []T) enumerators.Enumerator[T] {
	emitted := false
	return enumerators.PageItemEnumerator(func() ([]T, bool, error) {
		if emitted {
			return nil, false, nil
		}
		emitted = true
		return items, false, nil
	})
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenAccountCollectorRunsWithInjectedClient(t *testing.T) {
	testCases := []struct {
		mode             string
		expectedRootRefs []string
		expectedTargets  int
	}{{
		mode:             options.ModeSingle,
		expectedRootRefs: []string{"arn:aws:organizations::123456789012:account/o-example/123456789012"},
		expectedTargets:  1,
	}, {
		mode:             options.ModeOrganization,
		expectedRootRefs: []string{"arn:aws:iam::123456789012:root", "arn:aws:iam::210987654321:root"},
		expectedTargets:  2,
	}}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSAccountEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSAccountEntityCollectorOptions{
					AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
					AWSScopeOptionsCore:         contractScopeOptions(tc.mode),
					AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
				}),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsAccountEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, []any{
				&entities.Account{},
				&entities.GroupMember{},
				&entities.AccountRole{},
			}, (&options.AWSAccountEntityCollectorOptions{}).GetSpaces())

			rootRefs := map[string]bool{}
			for _, ref := range tc.expectedRootRefs {
				rootRefs[ref] = true
			}

			servicePrincipalCount := 0
			humanAssumableRoleCount := 0
			seenExpectedRefs := map[string]bool{
				"arn:aws:iam::123456789012:user/alice":  false,
				"arn:aws:iam::123456789012:role/admins": false,
				"idstore-user-1":                        false,
			}
			for _, ref := range tc.expectedRootRefs {
				seenExpectedRefs[ref] = false
			}
			for _, emitted := range emitter.emitted {
				account, ok := emitted.(*entities.Account)
				if !ok {
					continue
				}
				if _, ok := seenExpectedRefs[account.AccountRef]; ok {
					seenExpectedRefs[account.AccountRef] = true
				}
				if account.AccountRef == "arn:aws:iam::123456789012:role/admins" {
					require.Equal(t, types.AccountTypeServicePrincipal, account.AccountType)
					require.True(t, account.Enabled)
					require.Equal(t, "Admins role", account.Description)
					servicePrincipalCount++
				}
				if account.AccountRef == "arn:aws:iam::123456789012:role/human-assumable" {
					humanAssumableRoleCount++
				}
				if account.AccountRef == "arn:aws:iam::123456789012:user/alice" ||
					account.AccountRef == "idstore-user-1" {
					require.Empty(t, account.Description)
				}
				if rootRefs[account.AccountRef] {
					require.Empty(t, account.Description)
					require.Equal(t, types.AccountTypeRoot, account.AccountType)
				}
			}

			require.Equal(t, tc.expectedTargets, servicePrincipalCount)
			require.Zero(t, humanAssumableRoleCount)
			for ref, seen := range seenExpectedRefs {
				require.Truef(t, seen, "expected emitted account ref %s", ref)
			}

			accountRoles := make([]*entities.AccountRole, 0)
			for _, emitted := range emitter.emitted {
				if accountRole, ok := emitted.(*entities.AccountRole); ok {
					accountRoles = append(accountRoles, accountRole)
				}
			}
			require.Len(t, accountRoles, tc.expectedTargets)
			for _, accountRole := range accountRoles {
				require.Equal(t, "arn:aws:iam::123456789012:user/alice", accountRole.AccountRef)
				require.Equal(t, "role-2", accountRole.RoleRef)
			}
		})
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenGroupCollectorRunsWithInjectedClient(t *testing.T) {
	for _, mode := range contractModes {
		t.Run(mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSGroupEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSGroupEntityCollectorOptions{
					AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
					AWSScopeOptionsCore:         contractScopeOptions(mode),
					AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
				}),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsGroupEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, []any{
				&entities.Group{},
			}, (&options.AWSGroupEntityCollectorOptions{}).GetSpaces())
		})
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenRoleCollectorRunsWithInjectedClient(t *testing.T) {
	for _, mode := range contractModes {
		t.Run(mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSRoleEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSRoleEntityCollectorOptions{
					AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
					AWSScopeOptionsCore:      contractScopeOptions(mode),
					CollectInlinePolicies:    true,
				}),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsRoleEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, []any{
				&entities.Role{},
				&entities.Permission{},
				&entities.RolePermission{},
			}, (&options.AWSRoleEntityCollectorOptions{}).GetSpaces())
		})
	}
}

// fakeResourceOrgClient backs the resource collector's organization-tree walk
// with a root holding the management account and one OU holding the member account.
type fakeResourceOrgClient struct{}

func (fakeResourceOrgClient) OrganizationRootEnumerator(
	_ context.Context,
) enumerators.Enumerator[api.OrganizationalUnit] {
	return sliceEnumerator([]api.OrganizationalUnit{{ID: "r-1", Name: "Root"}})
}

func (fakeResourceOrgClient) OrganizationalUnitsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.OrganizationalUnit] {
	if parentID == "r-1" {
		return sliceEnumerator([]api.OrganizationalUnit{{ID: "ou-1", Name: "Workloads"}})
	}
	return sliceEnumerator([]api.OrganizationalUnit{})
}

func (fakeResourceOrgClient) OrganizationAccountsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.Account] {
	switch parentID {
	case "r-1":
		return sliceEnumerator([]api.Account{{
			ID:     "123456789012",
			Name:   "management",
			Status: api.AccountStatusActive,
		}})
	case "ou-1":
		return sliceEnumerator([]api.Account{{
			ID:     "210987654321",
			Name:   "member",
			Status: api.AccountStatusActive,
		}})
	default:
		return sliceEnumerator([]api.Account{})
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenResourceCollectorRunsWithInjectedClient(t *testing.T) {
	testCases := []struct {
		mode           string
		allowedTypes   []any
		expectedSpaces []spaces.Space
	}{{
		mode: options.ModeSingle,
		allowedTypes: []any{
			&entities.Resource{},
			&entities.ResourceContainer{},
			&entities.ResourceContainerResource{},
		},
		expectedSpaces: []spaces.Space{
			spaces.ResourceContainerResources,
			spaces.ResourceContainers,
			spaces.Resources,
		},
	}, {
		mode: options.ModeOrganization,
		allowedTypes: []any{
			&entities.Resource{},
			&entities.ResourceContainer{},
			&entities.ResourceContainerResource{},
			&entities.ResourceContainerResourceContainer{},
		},
		expectedSpaces: (&options.AWSResourceEntityCollectorOptions{}).GetSpaces(),
	}}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSResourceEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(
					t,
					emitter,
					&options.AWSResourceEntityCollectorOptions{
						AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
						AWSScopeOptionsCore:      contractScopeOptions(tc.mode),
					},
				),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsResourceEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				newOrgClient: func(_ *api.AWSCredentials, _, _ string) (awsResourceOrgClient, error) {
					return fakeResourceOrgClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, tc.allowedTypes, tc.expectedSpaces)
		})
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenPolicyCollectorRunsWithInjectedClient(t *testing.T) {
	for _, mode := range contractModes {
		t.Run(mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSPolicyEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSPolicyEntityCollectorOptions{
					AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
					AWSScopeOptionsCore:      contractScopeOptions(mode),
				}),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsPolicyEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, []any{
				&entities.Policy{},
			}, (&options.AWSPolicyEntityCollectorOptions{}).GetSpaces())
		})
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenMFACollectorRunsWithInjectedClient(t *testing.T) {
	for _, mode := range contractModes {
		t.Run(mode, func(t *testing.T) {
			emitter := &captureEntityEmitter{}
			collector := &AWSMFAEntityCollector{
				TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSMFAEntityCollectorOptions{
					AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
					AWSScopeOptionsCore:      contractScopeOptions(mode),
				}),
				newClient: func(_ *api.AWSCredentials, _, _ string) (awsMFAEntityClient, error) {
					return fakeAWSContractClient{}, nil
				},
				resolverOpts: contractResolverOpts(),
			}

			require.NoError(t, collector.Init(t.Context()))
			require.NoError(t, collector.Start(t.Context()))
			require.NoError(t, collector.Stop(t.Context()))

			assertEmittedEntityContract(t, emitter.emitted, []any{
				&entities.MultiFactor{},
				&entities.AccountMultiFactor{},
			}, (&options.AWSMFAEntityCollectorOptions{}).GetSpaces())
		})
	}
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

	credentials := map[string]json.RawMessage{
		connectorutil.DefaultCredentialName: apiKeyAndSecretCredential,
	}

	return connector.NewTypedFeatureContext[T, *connector.NoPayload](
		connector.NewFeatureContext(
			connector.WithConfiguration(&connector.Configuration{
				TenantID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
				ConnectorID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
				Options:     polymorphic.NewEnvelope(featureOptions),
				Credentials: credentials,
			}),
			connector.WithEmitter(emitter),
		),
	)
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

	observedTypeSet := map[string]struct{}{}
	observedSpaces := map[spaces.Space]struct{}{}
	for _, item := range emitted {
		typeName := reflect.TypeOf(item).String()
		if _, ok := allowedTypeSet[typeName]; !ok {
			t.Fatalf("unexpected emitted entity type %s", typeName)
		}
		observedTypeSet[typeName] = struct{}{}

		space, ok := emittedEntitySpace(item)
		if !ok {
			t.Fatalf("unexpected emitted entity type %s", typeName)
		}
		observedSpaces[space] = struct{}{}
	}

	if len(emitted) == 0 {
		t.Fatal("expected at least one emitted entity")
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

func emittedEntitySpace(item any) (spaces.Space, bool) {
	switch item.(type) {
	case *entities.Account:
		return spaces.Accounts, true
	case *entities.GroupMember:
		return spaces.GroupMembers, true
	case *entities.Group:
		return spaces.Groups, true
	case *entities.Role:
		return spaces.Roles, true
	case *entities.Permission:
		return spaces.Permissions, true
	case *entities.RolePermission:
		return spaces.RolePermissions, true
	case *entities.Resource:
		return spaces.Resources, true
	case *entities.ResourceContainer:
		return spaces.ResourceContainers, true
	case *entities.ResourceContainerResource:
		return spaces.ResourceContainerResources, true
	case *entities.ResourceContainerResourceContainer:
		return spaces.ResourceContainerResourceContainers, true
	case *entities.AccountRole:
		return spaces.AccountRoles, true
	case *entities.Policy:
		return spaces.Policies, true
	case *entities.MultiFactor:
		return spaces.MultiFactors, true
	case *entities.AccountMultiFactor:
		return spaces.AccountMultiFactors, true
	default:
		return "", false
	}
}
