package main

import (
	"log"

	"github.com/hydn-co/mesh-aws/internal/actions"
	"github.com/hydn-co/mesh-aws/internal/collectors"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

func main() {
	runner.Run(WithManifest())
}

func WithManifest() *runner.Manifest {
	manifest := runner.CreateManifest(
		"mesh-aws",
		"",
		"Amazon Web Services",
		"Mesh integration with Amazon Web Services",
	)

	manifest.MustRegisterFeature(
		"aws_account_entity_collector",
		"Collect Accounts",
		"Collects IAM users, Identity Store users, the management account, and group membership links as account-space data.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSAccountEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSAccountEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_group_entity_collector",
		"Collect Groups",
		"Collects IAM groups and Identity Store groups as group entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSGroupEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSGroupEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_role_entity_collector",
		"Collect Roles",
		"Collects IAM roles as role entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSRoleEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSRoleEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_policy_entity_collector",
		"Collect Policies",
		"Collects IAM local policies as policy entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSPolicyEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSPolicyEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_mfa_entity_collector",
		"Collect MFA Devices",
		"Collects IAM virtual MFA devices and account MFA links.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSMFAEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSMFAEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_cloudtrail_activity_collector",
		"Collect CloudTrail Activity",
		"Collects CloudTrail ConsoleLogin events and emits login activity events.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSCloudTrailActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSCloudTrailActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_sso_login_activity_collector",
		"Collect SSO Login Activity",
		"Collects IAM Identity Center login activity from CloudTrail and emits login activity events.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSSSOLoginActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(collectors.NewAWSSSOLoginActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_add_user_to_group_action",
		"Add User to Group",
		"Adds an IAM user to an IAM group.",
		runner.FeatureUnschedulable,
		runner.FeatureTypeAction,
		new(options.AWSAddUserToGroupActionOptions),
		new(payloads.AWSAddUserToGroupPayload),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(actions.NewAWSAddUserToGroupAction),
	)

	if err := manifest.Validate(); err != nil {
		log.Fatal(err)
	}

	return manifest
}
