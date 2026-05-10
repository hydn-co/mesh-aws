package main

import (
	"github.com/hydn-co/mesh-aws/internal/actions"
	"github.com/hydn-co/mesh-aws/internal/collectors"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

func main() {
	manifest := runner.CreateManifest(
		"aws",
		"",
		"Amazon Web Services",
		"Collects IAM users, groups, roles, policies and CloudTrail activity from AWS.",
	)

	manifest.MustRegisterFeature("collect-users", "Collect IAM Users",
		"Lists all IAM users and emits Account entities.",
		runner.FeatureSchedulable, runner.FeatureTypeCollector,
		&options.UsersOptions{}, (*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(collectors.NewIAMUserEntityCollector),
	)

	manifest.MustRegisterFeature("collect-groups", "Collect IAM Groups",
		"Lists all IAM groups and emits Group entities.",
		runner.FeatureSchedulable, runner.FeatureTypeCollector,
		&options.GroupsOptions{}, (*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(collectors.NewIAMGroupEntityCollector),
	)

	manifest.MustRegisterFeature("collect-roles", "Collect IAM Roles",
		"Lists all IAM roles and emits Role entities.",
		runner.FeatureSchedulable, runner.FeatureTypeCollector,
		&options.RolesOptions{}, (*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(collectors.NewIAMRoleEntityCollector),
	)

	manifest.MustRegisterFeature(
		"collect-policies",
		"Collect IAM Policies",
		"Lists all customer-managed IAM policies and emits Policy entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.PoliciesOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewIAMPolicyEntityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-virtual-mfa-devices",
		"Collect IAM Virtual MFA Devices",
		"Lists IAM virtual MFA devices and emits multi-factor entities and account bindings.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.VirtualMFADevicesOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewIAMVirtualMFADeviceEntityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-identity-store-users",
		"Collect Identity Store Users",
		"Lists AWS Identity Store users and emits account entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.IdentityStoreUsersOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewIdentityStoreUserEntityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-identity-store-groups",
		"Collect Identity Store Groups",
		"Lists AWS Identity Store groups and emits group entities.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.IdentityStoreGroupsOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewIdentityStoreGroupEntityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-master-account",
		"Collect Organization Master Account",
		"Describes the AWS organization and emits the management account as an account entity.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.MasterAccountOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewMasterAccountEntityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-activity",
		"Collect CloudTrail Activity",
		"Collects ConsoleLogin events from CloudTrail and emits login activity events.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.ActivityOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewCloudTrailActivityCollector,
		),
	)

	manifest.MustRegisterFeature(
		"collect-sso-activity",
		"Collect AWS SSO Activity",
		"Collects AWS SSO login activity from CloudTrail and emits login activity events.",
		runner.FeatureSchedulable,
		runner.FeatureTypeCollector,
		&options.SSOActivityOptions{},
		(*connector.NoPayload)(nil),
		runner.FeatureResumeBehaviorLastActivity,
		runner.AWSAccessKeyCredential,
		runner.Factory(
			collectors.NewSSOLoginActivityCollector,
		),
	)

	manifest.MustRegisterFeature("add-user-to-group", "Add User to Group",
		"Adds an IAM user to an IAM group.",
		runner.FeatureUnschedulable, runner.FeatureTypeAction,
		&options.GroupsOptions{}, &payloads.AddUserToGroupPayload{},
		runner.FeatureResumeBehaviorNone,
		runner.AWSAccessKeyCredential,
		runner.Factory(actions.NewAddUserToGroupAction),
	)

	runner.Run(manifest)
}
