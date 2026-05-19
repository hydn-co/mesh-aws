# mesh-aws

AWS mesh connector for collecting IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center data.

## What it exposes

- `aws_account_entity_collector` emits account entities for IAM users, Identity Store users, the Organizations management account, and group membership links.
- `aws_group_entity_collector` emits group entities for IAM groups and Identity Store groups.
- `aws_role_entity_collector` emits IAM role entities.
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

The connector now separates authentication from connection settings.

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
- `session_token` is optional and is only needed for temporary credentials.
- `identity_store_id` is required for the account and group collectors.

## Notes

- AWS region support is intentionally exposed as a select list because the set of regions changes slowly enough to maintain centrally.
- Activity collectors are split by catalog type: login activity and session activity are separate features.

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