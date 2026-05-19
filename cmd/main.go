package main

import (
	"log"

	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/actions"
	"github.com/hydn-co/mesh-aws/internal/collectors/activity"
	"github.com/hydn-co/mesh-aws/internal/collectors/entity"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
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
		runner.Factory(entity.NewAWSAccountEntityCollector),
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
		runner.Factory(entity.NewAWSGroupEntityCollector),
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
		runner.Factory(entity.NewAWSRoleEntityCollector),
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
		runner.Factory(entity.NewAWSPolicyEntityCollector),
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
		runner.Factory(entity.NewAWSMFAEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_login_activity_collector",
		"Collect Login Activity",
		"Collects AWS Management Console and IAM Identity Center login success and failure activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSLoginActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSLoginActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_session_activity_collector",
		"Collect Session Activity",
		"Collects IAM Identity Center session start and logout activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSSessionActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSSessionActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_cognito_user_pool_admin_activity_collector",
		"Collect Cognito User Pool Admin Activity",
		"Collects Amazon Cognito user pool administrative activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSCognitoUserPoolAdminActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSCognitoUserPoolAdminActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_group_activity_collector",
		"Collect Group Activity",
		"Collects IAM and Identity Store group creation and deletion activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSGroupActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSGroupActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_group_membership_activity_collector",
		"Collect Group Membership Activity",
		"Collects IAM and Identity Store group membership add and remove activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSGroupMembershipActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSGroupMembershipActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_role_activity_collector",
		"Collect Role Activity",
		"Collects IAM role, policy, and permission set creation and deletion activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSRoleActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSRoleActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_entitlement_activity_collector",
		"Collect Entitlement Activity",
		"Collects IAM permission and policy change activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSEntitlementActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSEntitlementActivityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_account_activity_collector",
		"Collect Account Activity",
		"Collects IAM user and AWS Organizations account creation and deletion activity from CloudTrail.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSAccountActivityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.APIKeyAndSecretCredential,
		runner.Factory(activity.NewAWSAccountActivityCollector),
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

	manifest.MustRegisterFeature(
		"aws_create_user_action",
		"Provision User",
		"Creates a new IAM user.",
		runner.FeatureUnschedulable,
		runner.FeatureTypeAction,
		new(options.AWSCreateUserActionOptions),
		new(payloads.AWSCreateUserPayload),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(actions.NewAWSCreateUserAction),
	)

	manifest.MustRegisterFeature(
		"aws_create_group_action",
		"Provision Group",
		"Creates a new IAM group.",
		runner.FeatureUnschedulable,
		runner.FeatureTypeAction,
		new(options.AWSCreateGroupActionOptions),
		new(payloads.AWSCreateGroupPayload),
		runner.FeatureResumeBehaviorNone,
		runner.APIKeyAndSecretCredential,
		runner.Factory(actions.NewAWSCreateGroupAction),
	)

	if err := manifest.Validate(); err != nil {
		log.Fatal(err)
	}

	return manifest
}
