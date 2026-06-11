package mappings

import (
	"testing"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/stretchr/testify/require"
)

func TestShouldMapVerbPrefixToPermissionTypeWhenActionIsRecognized(t *testing.T) {
	// Arrange
	testCases := []struct {
		action   string
		expected types.PermissionType
	}{
		{"ec2:AllocateAddress", types.PermissionCreate},
		{"s3:CreateBucket", types.PermissionCreate},
		{"ec2:DescribeInstances", types.PermissionRead},
		{"s3:Get*", types.PermissionRead},
		{"s3:GetObject", types.PermissionRead},
		{"sqs:ReceiveMessage", types.PermissionRead},
		{"ec2:DisableImage", types.PermissionEdit},
		{"ec2:DisassociateAddress", types.PermissionEdit},
		{"ec2:ModifyInstanceAttribute", types.PermissionEdit},
		{"s3:PutObject", types.PermissionEdit},
		{"ec2:TerminateInstances", types.PermissionDelete},
		{"s3:DeleteBucket", types.PermissionDelete},
		{"ec2:RebootInstances", types.PermissionExecute},
		{"lambda:InvokeFunction", types.PermissionExecute},
		{"sts:AssumeRole", types.PermissionExecute},
	}

	for _, tc := range testCases {
		t.Run(tc.action, func(t *testing.T) {
			// Act
			mapped := MapAWSActionPermissionType(tc.action)

			// Assert
			require.Equal(t, tc.expected, mapped)
		})
	}
}

func TestShouldReturnUnknownWhenActionIsWildcardOrUnrecognized(t *testing.T) {
	// Arrange
	testCases := []struct {
		name   string
		action string
	}{
		{"empty", ""},
		{"global wildcard", "*"},
		{"service wildcard", "s3:*"},
		{"unrecognized verb", "iam:PassRole"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			mapped := MapAWSActionPermissionType(tc.action)

			// Assert
			require.Equal(t, types.PermissionUnknown, mapped)
		})
	}
}
