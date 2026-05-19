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
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/spaces"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/stretchr/testify/require"
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
		RoleID:      "role-2",
		RoleName:    "human-assumable",
		Arn:         "arn:aws:iam::123456789012:role/human-assumable",
		Description: "Human assumable role",
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
	emitter := &captureEntityEmitter{}
	collector := &AWSAccountEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSAccountEntityCollectorOptions{
			AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsAccountEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
	}

	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	assertEmittedEntityContract(t, emitter.emitted, []any{
		&entities.Account{},
		&entities.GroupMember{},
	}, (&options.AWSAccountEntityCollectorOptions{}).GetSpaces())

	servicePrincipalCount := 0
	humanAssumableRoleCount := 0
	seenExpectedRefs := map[string]bool{
		"arn:aws:iam::123456789012:user/alice":                               false,
		"arn:aws:iam::123456789012:role/admins":                              false,
		"idstore-user-1":                                                     false,
		"arn:aws:organizations::123456789012:account/o-example/123456789012": false,
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
		if account.AccountRef == "arn:aws:iam::123456789012:user/alice" {
			require.Empty(t, account.Description)
		}
		if account.AccountRef == "idstore-user-1" {
			require.Empty(t, account.Description)
		}
		if account.AccountRef == "arn:aws:organizations::123456789012:account/o-example/123456789012" {
			require.Empty(t, account.Description)
		}
	}

	require.Equal(t, 1, servicePrincipalCount)
	require.Zero(t, humanAssumableRoleCount)
	for ref, seen := range seenExpectedRefs {
		require.Truef(t, seen, "expected emitted account ref %s", ref)
	}
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenGroupCollectorRunsWithInjectedClient(t *testing.T) {
	emitter := &captureEntityEmitter{}
	collector := &AWSGroupEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSGroupEntityCollectorOptions{
			AWSConnectionOptionsCore:    options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSIdentityStoreOptionsCore: options.AWSIdentityStoreOptionsCore{IdentityStoreID: "d-1234567890"},
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsGroupEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
	}

	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	assertEmittedEntityContract(t, emitter.emitted, []any{
		&entities.Group{},
	}, (&options.AWSGroupEntityCollectorOptions{}).GetSpaces())
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenRoleCollectorRunsWithInjectedClient(t *testing.T) {
	emitter := &captureEntityEmitter{}
	collector := &AWSRoleEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSRoleEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsRoleEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
	}

	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	assertEmittedEntityContract(t, emitter.emitted, []any{
		&entities.Role{},
	}, (&options.AWSRoleEntityCollectorOptions{}).GetSpaces())
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenPolicyCollectorRunsWithInjectedClient(t *testing.T) {
	emitter := &captureEntityEmitter{}
	collector := &AWSPolicyEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSPolicyEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsPolicyEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
	}

	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	assertEmittedEntityContract(t, emitter.emitted, []any{
		&entities.Policy{},
	}, (&options.AWSPolicyEntityCollectorOptions{}).GetSpaces())
}

func TestShouldOnlyEmitDeclaredEntityTypesWhenMFACollectorRunsWithInjectedClient(t *testing.T) {
	emitter := &captureEntityEmitter{}
	collector := &AWSMFAEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSMFAEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsMFAEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
	}

	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))
	require.NoError(t, collector.Stop(t.Context()))

	assertEmittedEntityContract(t, emitter.emitted, []any{
		&entities.MultiFactor{},
		&entities.AccountMultiFactor{},
	}, (&options.AWSMFAEntityCollectorOptions{}).GetSpaces())
}

func newAWSContractFeatureContext[T connector.FeatureOptions](
	t *testing.T,
	emitter *captureEntityEmitter,
	featureOptions T,
) *connector.TypedFeatureContext[T, *connector.NoPayload] {
	t.Helper()

	credentials, err := json.Marshal(map[string]string{
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
