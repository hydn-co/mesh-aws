package entity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/substrate/enumerators"
	"github.com/hydn-co/substrate/json/polymorphic"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/scope"
)

// captureEntityEmitter captures all emitted entities for assertions.
type captureEntityEmitter struct {
	emitted []any
}

func (e *captureEntityEmitter) Emit(_ context.Context, entity any) error {
	e.emitted = append(e.emitted, entity)
	return nil
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
