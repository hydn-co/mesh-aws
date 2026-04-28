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

	mustRegister(manifest, "collect-users", "Collect IAM Users",
		"Lists all IAM users and emits Account entities.",
		true, runner.FeatureTypeCollector,
		&options.UsersOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(collectors.NewIAMUserEntityCollector),
	)

	mustRegister(manifest, "collect-groups", "Collect IAM Groups",
		"Lists all IAM groups and emits Group entities.",
		true, runner.FeatureTypeCollector,
		&options.GroupsOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(collectors.NewIAMGroupEntityCollector),
	)

	mustRegister(manifest, "collect-roles", "Collect IAM Roles",
		"Lists all IAM roles and emits Role entities.",
		true, runner.FeatureTypeCollector,
		&options.RolesOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(collectors.NewIAMRoleEntityCollector),
	)

	mustRegister(
		manifest,
		"collect-policies",
		"Collect IAM Policies",
		"Lists all customer-managed IAM policies and emits Policy entities.",
		true,
		runner.FeatureTypeCollector,
		&options.PoliciesOptions{},
		nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(
			collectors.NewIAMPolicyEntityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-virtual-mfa-devices",
		"Collect IAM Virtual MFA Devices",
		"Lists IAM virtual MFA devices and emits multi-factor entities and account bindings.",
		true,
		runner.FeatureTypeCollector,
		&options.VirtualMFADevicesOptions{},
		nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(
			collectors.NewIAMVirtualMFADeviceEntityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-identity-store-users",
		"Collect Identity Store Users",
		"Lists AWS Identity Store users and emits account entities.",
		true,
		runner.FeatureTypeCollector,
		&options.IdentityStoreUsersOptions{},
		nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(
			collectors.NewIdentityStoreUserEntityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-identity-store-groups",
		"Collect Identity Store Groups",
		"Lists AWS Identity Store groups and emits group entities.",
		true,
		runner.FeatureTypeCollector,
		&options.IdentityStoreGroupsOptions{},
		nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(
			collectors.NewIdentityStoreGroupEntityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-master-account",
		"Collect Organization Master Account",
		"Describes the AWS organization and emits the management account as an account entity.",
		true,
		runner.FeatureTypeCollector,
		&options.MasterAccountOptions{},
		nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory(
			collectors.NewMasterAccountEntityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-activity",
		"Collect CloudTrail Activity",
		"Collects ConsoleLogin events from CloudTrail and emits login activity events.",
		true,
		runner.FeatureTypeCollector,
		&options.ActivityOptions{},
		nil,
		runner.FeatureResumeBehaviorLastActivity,
		runner.Factory(
			collectors.NewCloudTrailActivityCollector,
		),
	)

	mustRegister(
		manifest,
		"collect-sso-activity",
		"Collect AWS SSO Activity",
		"Collects AWS SSO login activity from CloudTrail and emits login activity events.",
		true,
		runner.FeatureTypeCollector,
		&options.SSOActivityOptions{},
		nil,
		runner.FeatureResumeBehaviorLastActivity,
		runner.Factory(
			collectors.NewSSOLoginActivityCollector,
		),
	)

	mustRegister(manifest, "add-user-to-group", "Add User to Group",
		"Adds an IAM user to an IAM group.",
		false, runner.FeatureTypeAction,
		&options.GroupsOptions{}, &payloads.AddUserToGroupPayload{},
		runner.FeatureResumeBehaviorNone,
		runner.Factory(actions.NewAddUserToGroupAction),
	)

	runner.Run(manifest)
}

func mustRegister(
	manifest *runner.Manifest,
	name, displayName, description string,
	schedulable bool,
	featureType runner.FeatureType,
	opts connector.FeatureOptions,
	payload connector.FeaturePayload,
	resumeBehavior runner.FeatureResumeBehavior,
	factory func(options ...connector.FeatureContextOption) runner.Feature,
) {
	if err := manifest.RegisterFeature(
		name, displayName, description,
		schedulable, featureType,
		opts, payload,
		resumeBehavior, "AWS Access Key",
		factory,
	); err != nil {
		panic("register feature " + name + ": " + err.Error())
	}
}
