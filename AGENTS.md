# mesh-aws

AWS mesh connector for IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center activity.

## Current surface

- `aws_account_entity_collector` emits account entities for IAM users, Identity Store users, the Organizations management account, and group membership links.
- `aws_group_entity_collector` emits group entities for IAM groups and Identity Store groups.
- `aws_role_entity_collector` emits IAM role entities plus one permission per IAM action the role's policies allow (mapped to a normalized CRUDE verb) and the role-permission links.
- `aws_resource_entity_collector` emits the scope hierarchy as resource containers (caller account in single mode; Organizations roots/OUs/accounts with nesting edges in organization mode) and tagged resources as classified resource entities with account-membership edges. Inventory comes from the Resource Groups Tagging API, so never-tagged resources are not returned. No `ScopedAssignment` entities are emitted — plain IAM has no principal→role-at-scope object; IAM Identity Center account assignments are the tracked follow-up source.
- `aws_policy_entity_collector` emits IAM managed policy entities.
- `aws_mfa_entity_collector` emits virtual MFA entities and account-to-MFA links.
- `aws_login_activity_collector` emits AWS Management Console and IAM Identity Center login success/failure activity.
- `aws_session_activity_collector` emits IAM Identity Center session start and logout activity.
- `aws_cognito_user_pool_admin_activity_collector` emits Amazon Cognito user pool administrative activity.
- `aws_add_user_to_group_action` adds an IAM user to an IAM group.

## Configuration notes

- Authentication credentials come from the `API Key and Secret` template as `api_key` and `api_secret`.
- Shared AWS connection settings live in `AWSConnectionOptionsCore`.
- `region` is a required option and is rendered as a select in the UI from the supported AWS region codes.
- `session_token` is optional and is only needed for temporary credentials such as STS-assumed roles.
- `identity_store_id` is required and applies to the account and group collectors when enumerating Identity Store data.

## Repository structure

```
cmd/            Entry point (main.go)
internal/
  api/          AWS HTTP client and service wrappers
  actions/      Action feature implementations
  collectors/
    activity/   Activity collector feature implementations
    entity/     Entity collector feature implementations
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
