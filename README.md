# mesh-aws

AWS mesh connector for collecting IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center data.

## What it exposes

- `aws_account_entity_collector` emits account entities for IAM users, Identity Store users, the Organizations management account, group membership links, and `AccountRole` links derived from each role's trust policy (the AWS principals permitted to assume the role).
- `aws_group_entity_collector` emits group entities for IAM groups and Identity Store groups.
- `aws_role_entity_collector` emits IAM role entities plus the `Permission` and `RolePermission` links for the policies that grant each role its access (attached managed policies always; role-embedded inline policies when `collect_inline_policies` is enabled).
- `aws_policy_entity_collector` emits IAM managed policy entities.
- `aws_mfa_entity_collector` emits virtual MFA entities and account-to-MFA links.
- `aws_login_activity_collector` emits AWS Management Console and IAM Identity Center login success/failure activity.
- `aws_session_activity_collector` emits IAM Identity Center session start and logout activity.
- `aws_group_activity_collector` emits group creation and deletion activity (IAM/Identity Store).
- `aws_group_membership_activity_collector` emits group membership add/remove activity.
- `aws_role_activity_collector` emits role, policy, and permission set lifecycle activity.
- `aws_entitlement_activity_collector` emits permission and policy change activity.
- `aws_account_activity_collector` emits account lifecycle activity.
- `aws_cognito_user_pool_admin_activity_collector` emits Amazon Cognito user pool administrative activity.
- `aws_add_user_to_group_action` adds an IAM user to an IAM group.
- `aws_create_user_action` creates a new IAM user.
- `aws_create_group_action` creates a new IAM group.

## Configuration

The connector separates authentication from connection settings.

Credentials:

```json
{
	"api_key": "AKIA...",
	"api_secret": "..."
}
```

`api_key` maps to the AWS access key ID, and `api_secret` maps to the AWS secret access key.

Shared AWS connection options:

- `region` is required and uses a select in the UI with supported AWS region codes.
- `session_token` is optional and is only needed for temporary credentials such as STS-assumed roles.
- `identity_store_id` is required for the account and group collectors.
- `collect_inline_policies` (role collector) is optional and defaults to off; when enabled the role collector also emits role-embedded inline policies as permissions.

## Required AWS permissions

The connector authenticates with a single AWS access key/secret (optionally a session token). Attach an IAM policy granting the actions below to the principal whose keys you configure. AWS IAM Query API actions are global (`us-east-1` signing scope); CloudTrail, Identity Store, and Organizations calls are made against the configured `region`. Grant only the rows for the features you enable; least-privilege deployments can omit write actions entirely.

### Collectors (read access)

| Feature | Minimum IAM actions | Grants |
|---------|---------------------|--------|
| `aws_account_entity_collector` | `iam:ListUsers`, `iam:ListGroupsForUser`, `iam:ListAccessKeys`, `iam:ListRoles`, `organizations:DescribeOrganization`, `identitystore:ListUsers`, `identitystore:ListGroups`, `identitystore:ListGroupMemberships` | Enumerate IAM users + access-key status, IAM group membership, Identity Store users/memberships, the management account, and role trust policies for `AccountRole` links |
| `aws_group_entity_collector` | `iam:ListGroups`, `identitystore:ListGroups` | Enumerate IAM and Identity Store groups |
| `aws_role_entity_collector` | `iam:ListRoles`, `iam:ListAttachedRolePolicies` | Enumerate IAM roles and their attached managed policies |
| `aws_role_entity_collector` (when `collect_inline_policies` is on) | `iam:ListRolePolicies` | Additionally enumerate role-embedded inline policies |
| `aws_policy_entity_collector` | `iam:ListPolicies` | Enumerate customer-managed IAM policies |
| `aws_mfa_entity_collector` | `iam:ListVirtualMFADevices` | Enumerate assigned virtual MFA devices |
| `aws_login_activity_collector` | `cloudtrail:LookupEvents` | Read console / Identity Center sign-in events |
| `aws_session_activity_collector` | `cloudtrail:LookupEvents` | Read Identity Center session start/logout events |
| `aws_group_activity_collector` | `cloudtrail:LookupEvents` | Read group create/delete events |
| `aws_group_membership_activity_collector` | `cloudtrail:LookupEvents` | Read group membership add/remove events |
| `aws_role_activity_collector` | `cloudtrail:LookupEvents` | Read role / policy / permission set lifecycle events |
| `aws_entitlement_activity_collector` | `cloudtrail:LookupEvents` | Read permission and policy change events |
| `aws_account_activity_collector` | `cloudtrail:LookupEvents` | Read IAM user and Organizations account lifecycle events |
| `aws_cognito_user_pool_admin_activity_collector` | `cloudtrail:LookupEvents` | Read Cognito user pool admin events |

### Actions (write access)

| Feature | Minimum IAM actions | Grants |
|---------|---------------------|--------|
| `aws_add_user_to_group_action` | `iam:AddUserToGroup` | Add an IAM user to an IAM group |
| `aws_create_user_action` | `iam:CreateUser` | Create an IAM user |
| `aws_create_group_action` | `iam:CreateGroup` | Create an IAM group |

### All features

| IAM action | Covers |
|------------|--------|
| `iam:ListUsers` | Account collector |
| `iam:ListGroups` | Group collector |
| `iam:ListGroupsForUser` | Account collector (IAM group membership) |
| `iam:ListAccessKeys` | Account collector (enabled-status detection) |
| `iam:ListRoles` | Account + role collectors |
| `iam:ListAttachedRolePolicies` | Role collector (managed permissions) |
| `iam:ListRolePolicies` | Role collector (inline permissions, when enabled) |
| `iam:ListPolicies` | Policy collector |
| `iam:ListVirtualMFADevices` | MFA collector |
| `organizations:DescribeOrganization` | Account collector (management account) |
| `identitystore:ListUsers` | Account collector (Identity Center users) |
| `identitystore:ListGroups` | Account + group collectors (Identity Center groups) |
| `identitystore:ListGroupMemberships` | Account collector (Identity Center memberships) |
| `cloudtrail:LookupEvents` | All activity collectors |
| `iam:AddUserToGroup` | Add-user-to-group action |
| `iam:CreateUser` | Provision-user action |
| `iam:CreateGroup` | Provision-group action |

## Notes

- AWS region support is intentionally exposed as a select list because the set of regions changes slowly enough to maintain centrally.
- Activity collectors are split by catalog type: login activity and session activity are separate features.
- `AccountRole` links are derived from role trust policies; account-root and cross-account principal ARNs are emitted as references even when no backing `Account` entity exists in the catalog.

## Repository structure

```text
cmd/            Entry point (main.go, manifest.json)
internal/
	api/          AWS HTTP client and service wrappers
	actions/      Action feature implementations
	collectors/
		activity/   Activity collector feature implementations
		entity/     Entity collector feature implementations
	options/      Feature option types and shared connection settings
	payloads/     Action payload types
```
