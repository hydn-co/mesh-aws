# mesh-aws

AWS mesh connector for collecting IAM, Identity Store, Organizations, CloudTrail, and IAM Identity Center data.

## What it exposes

- `aws_account_entity_collector` emits account entities for IAM users, Identity Store users, the Organizations management account, group membership links, and `AccountRole` links derived from each role's trust policy (the AWS principals permitted to assume the role).
- `aws_group_entity_collector` emits group entities for IAM groups and Identity Store groups.
- `aws_role_entity_collector` emits IAM role entities plus one `Permission` per IAM action the role's policies allow (classified into a normalized CRUDE verb) and the `RolePermission` links connecting them (attached managed policies always; role-embedded inline policies when `collect_inline_policies` is enabled).
- `aws_resource_entity_collector` emits the scope hierarchy as `ResourceContainer` entities (the caller's account in single mode; the Organizations roots, OUs, and member accounts — nested by `ResourceContainerResourceContainer` edges — in organization mode) and the tagged-resource inventory as classified `Resource` entities linked into their account by `ResourceContainerResource` edges.
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
- `aws_organization_entity_collector` emits the AWS Organizations hierarchy (roots, organizational units, and member accounts) as `OrganizationalUnit` entities with parent references.
- `aws_secret_entity_collector` emits AWS Secrets Manager secret metadata (ARN, name, rotation status — never secret values).
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

Every collector also takes a required `mode` (`single` or `organization`) plus the
organization-mode options described in [Organization-wide collection](#organization-wide-collection)
below. `mode` has no implicit default — it must be set explicitly.

## Organization-wide collection

Every collector runs in one of two modes, selected by the required `mode` option:

- **`single`** — collect from the one AWS account the configured credentials belong to
  (the connector's original behavior). Only the shared connection options apply.
- **`organization`** — point the connector at a management or delegated administrator
  account; it enumerates the AWS Organization's member accounts, assumes a cross-account
  discovery role into each, and fans collection out across them. One configured data source
  then covers the whole organization, so you do not stand up a collector per account.

### How organization mode works

1. The connector authenticates to the management/delegated account with the same
   `api_key` / `api_secret` credentials.
2. It lists member accounts via AWS Organizations (`ListAccounts`, or `ListAccountsForParent`
   when `organizational_unit_ids` is set — child OUs are included recursively). The
   `static_accounts` option bypasses enumeration entirely.
3. For each selected account it calls `sts:AssumeRole` on
   `arn:aws:iam::<account-id>:role/<assume_role_name>` (or the per-account `role_arn` from
   `static_accounts`), passing `external_id` when set, and collects with the returned
   temporary credentials. The management account itself is collected with the original
   credentials (no assume-role).
4. IAM is global, so identity collectors run once per account. Regional services (Secrets
   Manager) fan out across the `regions` list (defaulting to the primary `region`).
5. An account that fails to enumerate or assume is logged and **skipped** — one bad account
   never fails the whole run.

### Organization-mode options

These options are surfaced in the UI only when `mode` is `organization`.

| Option | Required | Purpose |
|--------|----------|---------|
| `assume_role_name` | Yes (unless `static_accounts` provide role ARNs) | Name of the cross-account discovery role to assume in each member account (e.g. `HyddenDiscoveryRole`). |
| `external_id` | No | `sts:ExternalId` value when the member-account role's trust policy requires it. |
| `include_account_ids` | No | If set, only these member account IDs are collected. |
| `exclude_account_ids` | No | Member account IDs to skip. |
| `organizational_unit_ids` | No | Limit collection to accounts within these OUs (and their child OUs). |
| `skip_management_account` | No | Exclude the management/delegated account from per-account collection. |
| `static_accounts` | No | Explicit `{account_id, role_arn}` entries that bypass Organizations enumeration (for customers who do not grant `organizations:ListAccounts`). |
| `regions` | No | Regions to scan for regional services (Secrets Manager). Defaults to the primary `region`. |

### Configuration examples

Single account:

```json
{ "mode": "single", "region": "us-east-1", "identity_store_id": "d-1234567890" }
```

Whole organization, assuming `HyddenDiscoveryRole` in every member account:

```json
{
	"mode": "organization",
	"region": "us-east-1",
	"assume_role_name": "HyddenDiscoveryRole",
	"external_id": "hydden-prod",
	"organizational_unit_ids": ["ou-root-workloads"],
	"exclude_account_ids": ["111111111111"],
	"regions": ["us-east-1", "eu-west-1"]
}
```

Explicit account list (no Organizations enumeration):

```json
{
	"mode": "organization",
	"region": "us-east-1",
	"static_accounts": [
		{ "account_id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/HyddenDiscoveryRole" }
	]
}
```

### Cross-account discovery role setup

Deploy a discovery role (named to match `assume_role_name`) into every member account —
CloudFormation StackSets with service-managed permissions is the scalable option, and can
auto-deploy the role to accounts added later. The role's trust policy allows the
management/collector principal to assume it:

```json
{
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "AllowHyddenCollectorAssumeRole",
		"Effect": "Allow",
		"Principal": { "AWS": "arn:aws:iam::<COLLECTOR_ACCOUNT_ID>:role/<COLLECTOR_ROLE>" },
		"Action": "sts:AssumeRole",
		"Condition": { "StringEquals": { "sts:ExternalId": "<external_id>" } }
	}]
}
```

Grant the discovery role the same read permissions the collectors need (see the tables
below) — IAM read for identity collectors, `secretsmanager:ListSecrets` for the secret
collector. Identity Center / `identitystore:*` is only available in the management/delegated
account, so Identity Store users and groups are collected once there, not per member account.

#### Deploy the role org-wide with a StackSet

[`deploy/cloudformation/`](deploy/cloudformation/) ships a CloudFormation template and a
cross-platform Python helper (`deploy_discovery_role.py`) that create the discovery role in
every member account using a **service-managed CloudFormation StackSet**, with
**auto-deployment** so accounts added to the organization later receive the role automatically.
Follow these steps from a machine with credentials for your **management or delegated-admin
account**:

**Step 1 — Install the prerequisites** (Python 3.9+):

```bash
pip install boto3
```

**Step 2 — Provide AWS credentials.** The helper uses boto3, which reads the standard AWS
credential chain — so authenticate to the **management or delegated-admin account** using any
of the usual methods before running it:

```bash
# Option A: a named profile (recommended)
export AWS_PROFILE=my-management-account     # configured via `aws configure --profile my-management-account` or SSO

# Option B: static keys / temporary STS credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...                 # only for temporary credentials
```

(`--dry-run` is the exception — it previews the plan without needing credentials.)

**Step 3 — Enable trusted access for StackSets** (one-time per organization; skip if already
enabled). The deploy helper can do this for you — just add `--activate-org-access` to the
deploy command the first time you run it. If you prefer the AWS CLI:

```bash
aws cloudformation activate-organizations-access
```

**Step 4 — Preview the deployment** with `--dry-run` (no changes are made; confirm the role
name, OUs, and excluded accounts look right):

```bash
python3 deploy/cloudformation/deploy_discovery_role.py \
    --ou-ids ou-root-workloads ou-root-sandbox \
    --external-id hydden-prod \
    --exclude-accounts 111111111111 222222222222 \
    --dry-run
```

**Step 5 — Deploy** by re-running the same command without `--dry-run`:

```bash
python3 deploy/cloudformation/deploy_discovery_role.py \
    --ou-ids ou-root-workloads ou-root-sandbox \
    --external-id hydden-prod \
    --exclude-accounts 111111111111 222222222222
```

To deploy to the entire organization with no exclusions, just run
`python3 deploy/cloudformation/deploy_discovery_role.py` (it defaults to the org root).

**Step 6 — Configure the connector** in organization mode with matching values:
`assume_role_name` = the role name (default `HyddenDiscoveryRole`), the same `external_id`, and
the same `exclude_account_ids` you passed to `--exclude-accounts`.

Reference for the flags used above:

| Flag | Meaning |
|------|---------|
| `--ou-ids` | Organizational units to deploy into. Defaults to the org root (whole organization). |
| `--exclude-accounts` | Accounts to skip (StackSet `AccountFilterType: DIFFERENCE`) — deploys to the chosen OUs **except** these, and keeps them excluded as the org grows. Mirror this in the connector's `exclude_account_ids`. |
| `--external-id` | `sts:ExternalId` baked into the role's trust policy; must equal the connector's `external_id`. |
| `--role-name` | Discovery role name (default `HyddenDiscoveryRole`); must equal the connector's `assume_role_name`. |
| `--collector-arn` | Principal allowed to assume the role. Defaults to the deploying identity (`aws sts get-caller-identity`); pass explicitly if the connector uses a different IAM user, or pass the account-root ARN. |
| `--region` | Home region for the StackSet (IAM is global, so one suffices). Defaults to your AWS config (`AWS_REGION` / `AWS_DEFAULT_REGION` / profile); required if none is configured. |

Note: service-managed StackSets do not target the management account itself — the connector
already collects it with its own credentials.

## Required AWS permissions

The connector authenticates with a single AWS access key/secret (optionally a session token). Attach an IAM policy granting the actions below to the principal whose keys you configure. AWS IAM Query API actions are global (`us-east-1` signing scope); CloudTrail, Identity Store, Organizations, Secrets Manager, and STS calls are made against the configured `region`. Grant only the rows for the features you enable; least-privilege deployments can omit write actions entirely.

In **organization mode** the rows below apply to two principals: each **member account's
discovery role** (deployed by the StackSet) gets the per-feature read actions, and the
**management/delegated principal** (the connector's own credentials) needs `organizations:List*`
+ `sts:AssumeRole` **and** these read actions (it also collects the management account and
Identity Center). See [Organization-mode management principal](#organization-mode-management-principal)
for a ready-to-attach policy.

### Collectors (read access)

| Feature | Minimum IAM actions | Grants |
|---------|---------------------|--------|
| `aws_account_entity_collector` | `iam:ListUsers`, `iam:ListGroupsForUser`, `iam:ListAccessKeys`, `iam:ListRoles`, `organizations:DescribeOrganization`, `identitystore:ListUsers`, `identitystore:ListGroups`, `identitystore:ListGroupMemberships` | Enumerate IAM users + access-key status, IAM group membership, Identity Store users/memberships, the management account, and role trust policies for `AccountRole` links |
| `aws_group_entity_collector` | `iam:ListGroups`, `identitystore:ListGroups` | Enumerate IAM and Identity Store groups |
| `aws_role_entity_collector` | `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion` | Enumerate IAM roles, their attached managed policies, and the IAM actions those policies allow |
| `aws_role_entity_collector` (when `collect_inline_policies` is on) | `iam:ListRolePolicies`, `iam:GetRolePolicy` | Additionally enumerate role-embedded inline policies and their allowed actions |
| `aws_resource_entity_collector` | `tag:GetResources`, `sts:GetCallerIdentity` (single mode), `organizations:ListRoots`, `organizations:ListOrganizationalUnitsForParent`, `organizations:ListAccountsForParent` (organization mode) | Enumerate tagged resources and the account/organization scope hierarchy |
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
| `aws_organization_entity_collector` | `organizations:ListRoots`, `organizations:ListOrganizationalUnitsForParent`, `organizations:ListAccountsForParent` | Enumerate the Organizations hierarchy (roots, OUs, member accounts) |
| `aws_secret_entity_collector` | `secretsmanager:ListSecrets` | Enumerate Secrets Manager secret metadata (no values) |

### Organization-mode management principal

Required only when `mode` is `organization`. In organization mode the connector's own
credentials belong to a **management or delegated-admin account principal** (the IAM user or
role whose access key you configure). That principal does two jobs, so it needs two sets of
permissions:

1. **Enumerate the organization and assume the member-account roles** — `organizations:List*`,
   `organizations:DescribeOrganization`, and `sts:AssumeRole`.
2. **Collect the management account itself, including Identity Center** — the management account
   is collected with these credentials directly (not via assume-role), and Identity Center
   (`identitystore:*`) is only readable here, not in member accounts. So this principal **also**
   needs the same read actions the collectors use (`iam`, `cloudtrail`, `secretsmanager`) plus
   `identitystore:List*`.

The discovery role deployed by `deploy/cloudformation/` covers the **member** accounts; this
policy is separate and goes on the **management principal**. Attach it to the IAM user/role
whose access key the connector uses (replace `HyddenDiscoveryRole` if you used a different
`--role-name`, and narrow the read `Resource: "*"` entries if your policy standards require it):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrganizationEnumeration",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "organizations:ListAccountsForParent",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AssumeDiscoveryRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/HyddenDiscoveryRole"
    },
    {
      "Sid": "ManagementAccountRead",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "cloudtrail:LookupEvents",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecretVersionIds",
        "tag:GetResources",
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "identitystore:ListGroupMemberships",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

The `ManagementAccountRead` statement can be trimmed to only the collectors you enable (e.g.
drop `secretsmanager:*` if you don't run the secret collector, or `identitystore:*` if you don't
use Identity Center). The `AssumeDiscoveryRole` resource can be tightened to specific account
IDs instead of `*`.

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
| `iam:GetPolicy`, `iam:GetPolicyVersion` | Role collector (managed-policy allowed actions) |
| `iam:ListRolePolicies` | Role collector (inline permissions, when enabled) |
| `iam:GetRolePolicy` | Role collector (inline-policy allowed actions, when enabled) |
| `iam:ListPolicies` | Policy collector |
| `iam:ListVirtualMFADevices` | MFA collector |
| `organizations:DescribeOrganization` | Account collector (management account); organization-mode management-account detection |
| `organizations:ListAccounts` | Organization mode (enumerate member accounts) |
| `organizations:ListAccountsForParent`, `organizations:ListRoots`, `organizations:ListOrganizationalUnitsForParent` | Organization entity collector; organization-mode OU scoping |
| `sts:AssumeRole` | Organization mode (cross-account discovery role) |
| `sts:GetCallerIdentity` | Resource collector (single-mode account container) |
| `tag:GetResources` | Resource collector (tagged-resource inventory) |
| `secretsmanager:ListSecrets` | Secret collector |
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
- In organization mode, emitted references already embed the account ID (IAM ARNs, secret ARNs), so data from many accounts coexists in the shared catalog spaces without collisions.
- The resource collector reads inventory from the Resource Groups Tagging API, chosen because it needs a single permission (`tag:GetResources`) and zero account setup. Its known blind spot: only resources that are or once were tagged are returned — never-tagged resources are invisible. AWS Config or Resource Explorer are future upgrades for full-inventory coverage.
- The role collector skips Deny statements and `NotAction` grants when expanding policy documents — the catalog has no per-permission deny dimension yet (follow-up).
- AWS emits no `ScopedAssignment` entities: plain IAM has no principal→role-at-scope object. IAM Identity Center account assignments (`sso-admin:ListInstances`/`ListPermissionSets`/`ListAccountAssignments` plus collecting permission sets as roles) are the natural source and are tracked as a follow-up.
- Organization mode currently targets the standard `aws` partition; GovCloud (`aws-us-gov`) and China (`aws-cn`) partitions are not yet handled in the assumed-role ARN.
- Activity collectors share a single resume cursor across all accounts in organization mode; duplicate event references are de-duplicated by the catalog's distinct identity.

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
