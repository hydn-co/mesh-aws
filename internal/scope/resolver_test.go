package scope

import (
	"context"
	"errors"
	"testing"

	"github.com/hydn-co/substrate/enumerators"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

// fakeOrgClient is an in-memory OrgClient for resolver tests.
type fakeOrgClient struct {
	master           string
	accounts         []api.Account
	accountsByParent map[string][]api.Account
	ousByParent      map[string][]api.OrganizationalUnit
	assumeErr        map[string]error
	assumeCalls      []string
}

func (f *fakeOrgClient) DescribeOrganization(context.Context) (*api.Organization, error) {
	if f.master == "" {
		return nil, errors.New("no organization")
	}
	return &api.Organization{MasterAccountID: f.master}, nil
}

func (f *fakeOrgClient) OrganizationAccountEnumerator(context.Context) enumerators.Enumerator[api.Account] {
	return enumerators.Slice(f.accounts)
}

func (f *fakeOrgClient) OrganizationAccountsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.Account] {
	return enumerators.Slice(f.accountsByParent[parentID])
}

func (f *fakeOrgClient) OrganizationalUnitsForParentEnumerator(
	_ context.Context,
	parentID string,
) enumerators.Enumerator[api.OrganizationalUnit] {
	return enumerators.Slice(f.ousByParent[parentID])
}

func (f *fakeOrgClient) AssumeRole(
	_ context.Context,
	roleArn, _, _ string,
) (*api.AssumedCredentials, error) {
	f.assumeCalls = append(f.assumeCalls, roleArn)
	if err := f.assumeErr[roleArn]; err != nil {
		return nil, err
	}
	return &api.AssumedCredentials{
		AccessKeyID:     "AK-" + roleArn,
		SecretAccessKey: "secret",
		SessionToken:    "token-" + roleArn,
	}, nil
}

func mgmtCreds() *api.AWSCredentials {
	return &api.AWSCredentials{AccessKeyID: "MGMT", SecretAccessKey: "mgmt-secret"}
}

func newTestResolver(opts *options.AWSScopeOptionsCore, fake *fakeOrgClient) *Resolver {
	return NewResolver(
		opts,
		"us-east-1",
		"mgmt-session",
		mgmtCreds(),
		WithOrgClientFactory(func(*api.AWSCredentials, string, string) (OrgClient, error) {
			return fake, nil
		}),
	)
}

func targetByAccount(targets []Target, accountID string) (Target, bool) {
	for _, target := range targets {
		if target.AccountID == accountID {
			return target, true
		}
	}
	return Target{}, false
}

func TestShouldYieldSingleManagementTargetWhenSingleMode(t *testing.T) {
	resolver := newTestResolver(&options.AWSScopeOptionsCore{Mode: options.ModeSingle}, &fakeOrgClient{})

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "", targets[0].AccountID)
	require.Equal(t, "us-east-1", targets[0].Region)
	require.Equal(t, "MGMT", targets[0].Credentials.AccessKeyID)
	require.Equal(t, "mgmt-session", targets[0].SessionToken)
}

func TestShouldAssumeRolePerMemberAndSkipSuspendedWhenOrganizationMode(t *testing.T) {
	fake := &fakeOrgClient{
		master: "111111111111",
		accounts: []api.Account{
			{ID: "111111111111", Name: "management", Status: api.AccountStatusActive},
			{ID: "222222222222", Name: "workload", Status: api.AccountStatusActive},
			{ID: "333333333333", Name: "suspended", Status: "SUSPENDED"},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:           options.ModeOrganization,
		AssumeRoleName: "HyddenDiscoveryRole",
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 2)

	// Management account uses management credentials directly (no AssumeRole).
	mgmt, ok := targetByAccount(targets, "111111111111")
	require.True(t, ok)
	require.Equal(t, "MGMT", mgmt.Credentials.AccessKeyID)

	// Member account is reached via an assumed role.
	member, ok := targetByAccount(targets, "222222222222")
	require.True(t, ok)
	require.Equal(t, "AK-arn:aws:iam::222222222222:role/HyddenDiscoveryRole", member.Credentials.AccessKeyID)
	require.Equal(t, "token-arn:aws:iam::222222222222:role/HyddenDiscoveryRole", member.SessionToken)

	require.Equal(t, []string{"arn:aws:iam::222222222222:role/HyddenDiscoveryRole"}, fake.assumeCalls)
}

func TestShouldHonorIncludeAndExcludeFiltersWhenOrganizationMode(t *testing.T) {
	fake := &fakeOrgClient{
		master: "111111111111",
		accounts: []api.Account{
			{ID: "111111111111", Status: api.AccountStatusActive},
			{ID: "222222222222", Status: api.AccountStatusActive},
			{ID: "333333333333", Status: api.AccountStatusActive},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:              options.ModeOrganization,
		AssumeRoleName:    "Role",
		IncludeAccountIDs: []string{"222222222222", "333333333333"},
		ExcludeAccountIDs: []string{"333333333333"},
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "222222222222", targets[0].AccountID)
}

func TestShouldSkipManagementAccountWhenConfigured(t *testing.T) {
	fake := &fakeOrgClient{
		master: "111111111111",
		accounts: []api.Account{
			{ID: "111111111111", Status: api.AccountStatusActive},
			{ID: "222222222222", Status: api.AccountStatusActive},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:                  options.ModeOrganization,
		AssumeRoleName:        "Role",
		SkipManagementAccount: true,
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "222222222222", targets[0].AccountID)
}

func TestShouldUseStaticAccountsWhenProvided(t *testing.T) {
	fake := &fakeOrgClient{
		// Enumeration would return nothing; static accounts must bypass it.
		accounts: nil,
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode: options.ModeOrganization,
		StaticAccounts: []options.StaticAccount{
			{AccountID: "444444444444", RoleArn: "arn:aws:iam::444444444444:role/Custom"},
		},
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "444444444444", targets[0].AccountID)
	require.Equal(t, "AK-arn:aws:iam::444444444444:role/Custom", targets[0].Credentials.AccessKeyID)
	require.Equal(t, []string{"arn:aws:iam::444444444444:role/Custom"}, fake.assumeCalls)
}

func TestShouldSkipAccountWhenAssumeRoleFails(t *testing.T) {
	failingRole := "arn:aws:iam::222222222222:role/Role"
	fake := &fakeOrgClient{
		master: "999999999999",
		accounts: []api.Account{
			{ID: "111111111111", Status: api.AccountStatusActive},
			{ID: "222222222222", Status: api.AccountStatusActive},
		},
		assumeErr: map[string]error{failingRole: errors.New("access denied")},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:           options.ModeOrganization,
		AssumeRoleName: "Role",
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 1)
	require.Equal(t, "111111111111", targets[0].AccountID)
}

func TestShouldExpandToOneTargetPerRegionWhenRegional(t *testing.T) {
	fake := &fakeOrgClient{
		master: "999999999999",
		accounts: []api.Account{
			{ID: "111111111111", Status: api.AccountStatusActive},
			{ID: "222222222222", Status: api.AccountStatusActive},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:           options.ModeOrganization,
		AssumeRoleName: "Role",
		Regions:        []string{"us-east-1", "eu-west-1"},
	}, fake)

	targets, err := resolver.Resolve(context.Background(), true)

	require.NoError(t, err)
	require.Len(t, targets, 4)

	regions := map[string]int{}
	for _, target := range targets {
		regions[target.Region]++
	}
	require.Equal(t, 2, regions["us-east-1"])
	require.Equal(t, 2, regions["eu-west-1"])
}

func TestShouldCollectAccountsWithinOrganizationalUnitScope(t *testing.T) {
	fake := &fakeOrgClient{
		master: "999999999999",
		accountsByParent: map[string][]api.Account{
			"ou-parent": {{ID: "111111111111", Status: api.AccountStatusActive}},
			"ou-child":  {{ID: "222222222222", Status: api.AccountStatusActive}},
		},
		ousByParent: map[string][]api.OrganizationalUnit{
			"ou-parent": {{ID: "ou-child", Name: "child"}},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:                  options.ModeOrganization,
		AssumeRoleName:        "Role",
		OrganizationalUnitIDs: []string{"ou-parent"},
	}, fake)

	targets, err := resolver.Resolve(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, targets, 2) // parent account + nested child OU account
	_, hasParentAccount := targetByAccount(targets, "111111111111")
	_, hasChildAccount := targetByAccount(targets, "222222222222")
	require.True(t, hasParentAccount)
	require.True(t, hasChildAccount)
}

func TestShouldPropagateCollectionErrorWhenSingleMode(t *testing.T) {
	resolver := newTestResolver(&options.AWSScopeOptionsCore{Mode: options.ModeSingle}, &fakeOrgClient{})

	wantErr := errors.New("boom")
	err := ForEachTarget(context.Background(), resolver, false,
		func(*api.AWSCredentials, string, string) (string, error) { return "client", nil },
		func(context.Context, string, Target) error { return wantErr },
	)

	require.ErrorIs(t, err, wantErr)
}

func TestShouldContinuePastFailingAccountWhenOrganizationMode(t *testing.T) {
	fake := &fakeOrgClient{
		master: "999999999999",
		accounts: []api.Account{
			{ID: "111111111111", Status: api.AccountStatusActive},
			{ID: "222222222222", Status: api.AccountStatusActive},
		},
	}
	resolver := newTestResolver(&options.AWSScopeOptionsCore{
		Mode:           options.ModeOrganization,
		AssumeRoleName: "Role",
	}, fake)

	visited := 0
	err := ForEachTarget(context.Background(), resolver, false,
		func(*api.AWSCredentials, string, string) (string, error) { return "client", nil },
		func(_ context.Context, _ string, target Target) error {
			visited++
			if target.AccountID == "111111111111" {
				return errors.New("collection failed")
			}
			return nil
		},
	)

	require.NoError(t, err)
	require.Equal(t, 2, visited) // failing account did not abort the run
}
