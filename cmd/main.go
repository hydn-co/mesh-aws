package main

import (
	"log"

	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"

	"github.com/hydn-co/mesh-aws/internal/actions"
	"github.com/hydn-co/mesh-aws/internal/collectors/activity"
	"github.com/hydn-co/mesh-aws/internal/collectors/entity"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
)

// awsCredentials declares the single access-key + secret credential every AWS
// feature uses. The slot is named connectorutil.DefaultCredentialName so
// bindings created before named credentials existed continue to resolve.
var awsCredentials = []runner.CredentialRequirement{
	{Name: connectorutil.DefaultCredentialName, TemplateName: runner.APIKeyAndSecretCredential},
}

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
		awsCredentials,
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
		awsCredentials,
		runner.Factory(entity.NewAWSGroupEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_role_entity_collector",
		"Collect Roles",
		"Collects IAM roles as role entities plus the IAM actions their policies allow as permissions.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSRoleEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		awsCredentials,
		runner.Factory(entity.NewAWSRoleEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_resource_entity_collector",
		"Collect Resources",
		"Collects the account/organization scope hierarchy as resource containers and tagged AWS resources as classified resource entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSResourceEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		awsCredentials,
		runner.Factory(entity.NewAWSResourceEntityCollector),
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
		awsCredentials,
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
		awsCredentials,
		runner.Factory(entity.NewAWSMFAEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_organization_entity_collector",
		"Collect Organization Hierarchy",
		"Collects the AWS Organizations hierarchy (roots, organizational units, and member accounts) as organizational-unit entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSOrganizationEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		awsCredentials,
		runner.Factory(entity.NewAWSOrganizationEntityCollector),
	)

	manifest.MustRegisterFeature(
		"aws_secret_entity_collector",
		"Collect Secrets",
		"Collects AWS Secrets Manager secret metadata (no secret values) as secret entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		new(options.AWSSecretEntityCollectorOptions),
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		awsCredentials,
		runner.Factory(entity.NewAWSSecretEntityCollector),
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
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
		awsCredentials,
		runner.Factory(actions.NewAWSCreateGroupAction),
	)

	if err := manifest.Validate(); err != nil {
		log.Fatal(err)
	}

	return manifest
}
