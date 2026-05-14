# mesh-aws

AWS mesh connector for IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center activity.

## Current surface

- `aws_account_entity_collector` emits account entities for IAM users, Identity Store users, the Organizations management account, and group membership links.
- `aws_group_entity_collector` emits group entities for IAM groups and Identity Store groups.
- `aws_role_entity_collector` emits IAM role entities.
- `aws_policy_entity_collector` emits IAM managed policy entities.
- `aws_mfa_entity_collector` emits virtual MFA entities and account-to-MFA links.
- `aws_cloudtrail_activity_collector` emits CloudTrail login activity.
- `aws_sso_login_activity_collector` emits IAM Identity Center login activity from CloudTrail.
- `aws_add_user_to_group_action` adds an IAM user to an IAM group.

## Configuration notes

- Authentication credentials are just `access_key_id` and `secret_access_key`.
- Shared AWS connection settings live in `AWSConnectionOptionsCore`.
- `region` is a required option and is rendered as a select in the UI from the supported AWS region codes.
- `session_token` is optional and is only needed for temporary credentials such as STS-assumed roles.
- `identity_store_id` is optional and applies to the account and group collectors when enumerating Identity Store data.

## Repository structure

```
cmd/            Entry point (main.go)
internal/
  api/          AWS HTTP client and service wrappers
  actions/      Action feature implementations
  collectors/   Collector feature implementations
  credentials/  AWS credential parsing
  options/      Feature option types and shared connection settings
  payloads/     Action payload types
.github/
  workflows/    CI, release, and version workflows
```

## Development commands

```bash
go build ./...
go vet ./...
go test ./...
go run ./cmd -describe
go run ./cmd -list
```
