package mappings

import (
	"testing"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/stretchr/testify/require"
)

func TestShouldClassifyARNWhenServiceAndTypeAreCurated(t *testing.T) {
	// Arrange
	testCases := []struct {
		arn      string
		expected types.ResourceType
	}{
		{"arn:aws:dynamodb:us-east-1:111111111111:table/orders", types.ResourceTypeNoSQLDatabase},
		{"arn:aws:ec2:us-east-1:111111111111:instance/i-0abc", types.ResourceTypeVirtualMachine},
		{"arn:aws:ec2:us-east-1:111111111111:security-group/sg-0abc", types.ResourceTypeFirewall},
		{"arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0abc", types.ResourceTypeVirtualNetwork},
		{
			"arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/abc",
			types.ResourceTypeLoadBalancer,
		},
		{"arn:aws:kms:us-east-1:111111111111:key/1234", types.ResourceTypeEncryptionKey},
		{"arn:aws:lambda:us-east-1:111111111111:function:fn-one", types.ResourceTypeServerlessFunction},
		{"arn:aws:rds:us-east-1:111111111111:db:prod-db", types.ResourceTypeDatabase},
		{"arn:aws:route53:::hostedzone/Z123", types.ResourceTypeDNSZone},
		{"arn:aws:s3:::my-bucket", types.ResourceTypeObjectStorage},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:db-creds-AbCdEf", types.ResourceTypeSecretStore},
		{"arn:aws:sqs:us-east-1:111111111111:work-queue", types.ResourceTypeMessageQueue},
		{"arn:aws:states:us-east-1:111111111111:stateMachine:flow", types.ResourceTypeIntegrationWorkflow},
	}

	for _, tc := range testCases {
		t.Run(tc.arn, func(t *testing.T) {
			// Act
			mapped := MapAWSResourceType(tc.arn)

			// Assert
			require.Equal(t, tc.expected, mapped)
		})
	}
}

func TestShouldReturnOtherWhenARNIsMalformedOrUnmapped(t *testing.T) {
	// Arrange
	testCases := []struct {
		name string
		arn  string
	}{
		{"empty", ""},
		{"not an arn", "i-0abc123"},
		{"too few segments", "arn:aws:s3"},
		{"unmapped service", "arn:aws:workspaces:us-east-1:111111111111:workspace/ws-0abc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			mapped := MapAWSResourceType(tc.arn)

			// Assert
			require.Equal(t, types.ResourceTypeOther, mapped)
		})
	}
}

func TestShouldOnlyMapToWellKnownResourceTypesWhenTablesAreCurated(t *testing.T) {
	// Arrange
	known := map[types.ResourceType]struct{}{}
	for _, rt := range types.AllResourceTypes() {
		known[rt] = struct{}{}
	}

	// Assert
	for key, rt := range awsResourceTypeMap {
		require.Containsf(t, known, rt, "awsResourceTypeMap[%q] maps to unknown ResourceType %q", key, rt)
	}
	for key, rt := range awsServiceResourceTypeMap {
		require.Containsf(t, known, rt, "awsServiceResourceTypeMap[%q] maps to unknown ResourceType %q", key, rt)
	}
}
