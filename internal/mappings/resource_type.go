package mappings

import (
	"strings"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
)

// awsResourceTypeMap maps lowercased "service/typePrefix" keys parsed from an ARN
// ("arn:aws:ec2:us-east-1:111111111111:instance/i-0abc" → "ec2/instance") onto
// the normalized catalog ResourceType. It is intentionally curated to the common,
// security-relevant AWS services; anything unmapped falls back to the
// service-level table below, then ResourceTypeOther (see MapAWSResourceType).
// The connector owns this mapping — the SDK only publishes the well-known set.
var awsResourceTypeMap = map[string]types.ResourceType{
	"backup/backup-vault":   types.ResourceTypeBackupVault,
	"dynamodb/table":        types.ResourceTypeNoSQLDatabase,
	"ec2/instance":          types.ResourceTypeVirtualMachine,
	"ec2/security-group":    types.ResourceTypeFirewall,
	"ec2/snapshot":          types.ResourceTypeBlockStorage,
	"ec2/subnet":            types.ResourceTypeSubnet,
	"ec2/volume":            types.ResourceTypeBlockStorage,
	"ec2/vpc":               types.ResourceTypeVirtualNetwork,
	"ecr/repository":        types.ResourceTypeContainerRegistry,
	"ecs/cluster":           types.ResourceTypeContainerCluster,
	"eks/cluster":           types.ResourceTypeContainerCluster,
	"elasticache/cluster":   types.ResourceTypeCache,
	"es/domain":             types.ResourceTypeSearchIndex,
	"kms/key":               types.ResourceTypeEncryptionKey,
	"lambda/function":       types.ResourceTypeServerlessFunction,
	"rds/cluster":           types.ResourceTypeDatabase,
	"rds/db":                types.ResourceTypeDatabase,
	"redshift/cluster":      types.ResourceTypeDataWarehouse,
	"route53/hostedzone":    types.ResourceTypeDNSZone,
	"secretsmanager/secret": types.ResourceTypeSecretStore,
	"ssm/parameter":         types.ResourceTypeSecretStore,
	"states/statemachine":   types.ResourceTypeIntegrationWorkflow,
}

// awsServiceResourceTypeMap maps lowercased ARN service namespaces onto the
// normalized catalog ResourceType for services whose resources all classify the
// same way regardless of resource type prefix (e.g. every SQS ARN is a queue).
var awsServiceResourceTypeMap = map[string]types.ResourceType{
	"acm":                  types.ResourceTypeCertificate,
	"apigateway":           types.ResourceTypeAPIGateway,
	"cloudfront":           types.ResourceTypeCDN,
	"cloudwatch":           types.ResourceTypeMonitoringWorkspace,
	"codeartifact":         types.ResourceTypeArtifactRegistry,
	"codebuild":            types.ResourceTypeCICDPipeline,
	"codecommit":           types.ResourceTypeRepository,
	"codepipeline":         types.ResourceTypeCICDPipeline,
	"elasticfilesystem":    types.ResourceTypeFileStorage,
	"elasticloadbalancing": types.ResourceTypeLoadBalancer,
	"kinesis":              types.ResourceTypeEventStream,
	"logs":                 types.ResourceTypeMonitoringWorkspace,
	"s3":                   types.ResourceTypeObjectStorage,
	"sagemaker":            types.ResourceTypeMachineLearning,
	"sns":                  types.ResourceTypeNotificationTopic,
	"sqs":                  types.ResourceTypeMessageQueue,
}

// MapAWSResourceType normalizes an AWS resource ARN into the catalog
// ResourceType taxonomy. The ARN's service namespace and leading resource-type
// segment ("ec2/instance") are matched first, then the service alone ("s3").
// Anything unrecognized — including malformed ARNs — maps to ResourceTypeOther,
// never empty, so the resource is still classified rather than dropped.
func MapAWSResourceType(arn string) types.ResourceType {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 6 || parts[0] != "arn" || parts[2] == "" {
		return types.ResourceTypeOther
	}

	service := strings.ToLower(parts[2])
	typePrefix := strings.ToLower(parts[5])
	if idx := strings.IndexAny(typePrefix, "/:"); idx >= 0 {
		typePrefix = typePrefix[:idx]
	}

	if rt, ok := awsResourceTypeMap[service+"/"+typePrefix]; ok {
		return rt
	}
	if rt, ok := awsServiceResourceTypeMap[service]; ok {
		return rt
	}
	return types.ResourceTypeOther
}
