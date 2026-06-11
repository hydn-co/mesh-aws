package entity

import (
	"testing"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/stretchr/testify/require"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

func newResourceCollectorForMode(
	t *testing.T,
	emitter *captureEntityEmitter,
	mode string,
) *AWSResourceEntityCollector {
	t.Helper()

	return &AWSResourceEntityCollector{
		TypedFeatureContext: newAWSContractFeatureContext(t, emitter, &options.AWSResourceEntityCollectorOptions{
			AWSConnectionOptionsCore: options.AWSConnectionOptionsCore{Region: "us-west-2"},
			AWSScopeOptionsCore:      contractScopeOptions(mode),
		}),
		newClient: func(_ *api.AWSCredentials, _, _ string) (awsResourceEntityClient, error) {
			return fakeAWSContractClient{}, nil
		},
		newOrgClient: func(_ *api.AWSCredentials, _, _ string) (awsResourceOrgClient, error) {
			return fakeResourceOrgClient{}, nil
		},
		resolverOpts: contractResolverOpts(),
	}
}

func emittedContainersByRef(emitted []any) map[string]*entities.ResourceContainer {
	containers := map[string]*entities.ResourceContainer{}
	for _, item := range emitted {
		if container, ok := item.(*entities.ResourceContainer); ok {
			containers[container.ContainerRef] = container
		}
	}
	return containers
}

func emittedNestingKeys(emitted []any) []string {
	keys := make([]string, 0)
	for _, item := range emitted {
		if nesting, ok := item.(*entities.ResourceContainerResourceContainer); ok {
			keys = append(keys, nesting.ParentContainerRef+"|"+nesting.ChildContainerRef)
		}
	}
	return keys
}

func emittedMembershipKeys(emitted []any) []string {
	keys := make([]string, 0)
	for _, item := range emitted {
		if membership, ok := item.(*entities.ResourceContainerResource); ok {
			keys = append(keys, membership.ContainerRef+"|"+membership.ResourceRef)
		}
	}
	return keys
}

func TestShouldEmitCallerAccountContainerAndClassifiedResourcesWhenSingleMode(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := newResourceCollectorForMode(t, emitter, options.ModeSingle)

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))

	// Assert: the caller's account is the one container and every resource hangs off it.
	containers := emittedContainersByRef(emitter.emitted)
	require.Len(t, containers, 1)
	require.Equal(t, entities.ContainerTypeAccount, containers["123456789012"].ContainerType)
	require.Empty(t, emittedNestingKeys(emitter.emitted))

	resources := map[string]*entities.Resource{}
	for _, item := range emitter.emitted {
		if resource, ok := item.(*entities.Resource); ok {
			resources[resource.ResourceRef] = resource
		}
	}
	require.Len(t, resources, 2)
	instance := resources["arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123"]
	require.Equal(t, "web-server", instance.Name, "Name tag preferred over the opaque ARN tail")
	require.Equal(t, types.ResourceTypeVirtualMachine, instance.ResourceType)
	bucket := resources["arn:aws:s3:::contract-bucket"]
	require.Equal(t, "contract-bucket", bucket.Name, "untagged: falls back to the ARN name segment")
	require.Equal(t, types.ResourceTypeObjectStorage, bucket.ResourceType)

	require.ElementsMatch(t, []string{
		"123456789012|arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123",
		"123456789012|arn:aws:s3:::contract-bucket",
	}, emittedMembershipKeys(emitter.emitted))
}

func TestShouldEmitOrganizationHierarchyWithNestingEdgesWhenOrganizationMode(t *testing.T) {
	// Arrange
	emitter := &captureEntityEmitter{}
	collector := newResourceCollectorForMode(t, emitter, options.ModeOrganization)

	// Act
	require.NoError(t, collector.Init(t.Context()))
	require.NoError(t, collector.Start(t.Context()))

	// Assert: the root and OU are management groups, the accounts are accounts,
	// and every container is nested under its parent.
	containers := emittedContainersByRef(emitter.emitted)
	require.Len(t, containers, 4)
	require.Equal(t, entities.ContainerTypeManagementGroup, containers["r-1"].ContainerType)
	require.Equal(t, entities.ContainerTypeManagementGroup, containers["ou-1"].ContainerType)
	require.Equal(t, entities.ContainerTypeAccount, containers["123456789012"].ContainerType)
	require.Equal(t, entities.ContainerTypeAccount, containers["210987654321"].ContainerType)
	require.Equal(t, "management", containers["123456789012"].Name)

	require.ElementsMatch(t, []string{
		"r-1|123456789012",
		"r-1|ou-1",
		"ou-1|210987654321",
	}, emittedNestingKeys(emitter.emitted))

	// The fake returns the same ARNs for both targets: resources dedupe by ARN
	// run-wide, so the membership edges land on the first target's account.
	resourceRefs := map[string]int{}
	for _, item := range emitter.emitted {
		if resource, ok := item.(*entities.Resource); ok {
			resourceRefs[resource.ResourceRef]++
		}
	}
	require.Len(t, resourceRefs, 2)
	for ref, count := range resourceRefs {
		require.Equalf(t, 1, count, "resource %s emitted more than once", ref)
	}
	require.ElementsMatch(t, []string{
		"123456789012|arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123",
		"123456789012|arn:aws:s3:::contract-bucket",
	}, emittedMembershipKeys(emitter.emitted))
}
