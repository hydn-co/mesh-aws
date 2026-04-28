package main

import (
	"github.com/hydn-co/mesh-aws/internal/actions"
	"github.com/hydn-co/mesh-aws/internal/collectors"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

const (
	secretTemplateName = "AWS Access Key"
	version            = ""
)

func main() {
	manifest := runner.CreateManifest(
		"aws",
		version,
		"Amazon Web Services",
		"Collects IAM users, groups, roles, policies and CloudTrail activity from AWS.",
	)

	mustRegister(manifest, "collect-users", "Collect IAM Users",
		"Lists all IAM users and emits Account entities.",
		true, runner.FeatureTypeCollector,
		&options.UsersOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.UsersOptions, *payloads.ActivityResumePayload](collectors.NewIAMUserEntityCollector),
	)

	mustRegister(manifest, "collect-groups", "Collect IAM Groups",
		"Lists all IAM groups and emits Group entities.",
		true, runner.FeatureTypeCollector,
		&options.GroupsOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.GroupsOptions, *payloads.ActivityResumePayload](collectors.NewIAMGroupEntityCollector),
	)

	mustRegister(manifest, "collect-roles", "Collect IAM Roles",
		"Lists all IAM roles and emits Role entities.",
		true, runner.FeatureTypeCollector,
		&options.RolesOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.RolesOptions, *payloads.ActivityResumePayload](collectors.NewIAMRoleEntityCollector),
	)

	mustRegister(manifest, "collect-policies", "Collect IAM Policies",
		"Lists all customer-managed IAM policies and emits Policy entities.",
		true, runner.FeatureTypeCollector,
		&options.PoliciesOptions{}, nil,
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.PoliciesOptions, *payloads.ActivityResumePayload](collectors.NewIAMPolicyEntityCollector),
	)

	mustRegister(manifest, "collect-activity", "Collect CloudTrail Activity",
		"Collects ConsoleLogin events from CloudTrail and emits login activity events.",
		true, runner.FeatureTypeCollector,
		&options.ActivityOptions{}, &payloads.ActivityResumePayload{},
		runner.FeatureResumeBehaviorLastActivity,
		runner.Factory[*options.ActivityOptions, *payloads.ActivityResumePayload](collectors.NewCloudTrailActivityCollector),
	)

	mustRegister(manifest, "disable-user", "Disable IAM User",
		"Deletes the login profile, deactivates access keys and MFA devices for an IAM user.",
		false, runner.FeatureTypeAction,
		&options.UsersOptions{}, &payloads.DisableUserPayload{},
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.UsersOptions, *payloads.DisableUserPayload](actions.NewDisableIAMUserAction),
	)

	mustRegister(manifest, "add-user-to-group", "Add User to Group",
		"Adds an IAM user to an IAM group.",
		false, runner.FeatureTypeAction,
		&options.GroupsOptions{}, &payloads.AddUserToGroupPayload{},
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.GroupsOptions, *payloads.AddUserToGroupPayload](actions.NewAddUserToGroupAction),
	)

	mustRegister(manifest, "remove-user-from-group", "Remove User from Group",
		"Removes an IAM user from an IAM group.",
		false, runner.FeatureTypeAction,
		&options.GroupsOptions{}, &payloads.RemoveUserFromGroupPayload{},
		runner.FeatureResumeBehaviorNone,
		runner.Factory[*options.GroupsOptions, *payloads.RemoveUserFromGroupPayload](actions.NewRemoveUserFromGroupAction),
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
		resumeBehavior, secretTemplateName,
		factory,
	); err != nil {
		panic("register feature " + name + ": " + err.Error())
	}
}
