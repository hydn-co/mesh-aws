# mesh-aws

AWS mesh connector for collecting IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center data.

## What it exposes

- `aws_account_entity_collector` for IAM users, Identity Store users, the Organizations management account, and group memberships.
- `aws_group_entity_collector` for IAM groups and Identity Store groups.
- `aws_role_entity_collector` for IAM roles.
- `aws_policy_entity_collector` for IAM managed policies.
- `aws_mfa_entity_collector` for virtual MFA devices and account-to-MFA links.
- `aws_cloudtrail_activity_collector` for CloudTrail login activity.
- `aws_sso_login_activity_collector` for IAM Identity Center login activity.
- `aws_add_user_to_group_action` for adding an IAM user to an IAM group.

## Configuration

The connector now separates authentication from connection settings.

Credentials:

```json
{
	"access_key_id": "AKIA...",
	"secret_access_key": "..."
}
```

Shared AWS connection options:

- `region` is required and uses a select in the UI with supported AWS region codes.
- `session_token` is optional and is only needed for temporary credentials.
- `identity_store_id` is optional for the account and group collectors.

## Notes

- AWS region support is intentionally exposed as a select list because the set of regions changes slowly enough to maintain centrally.