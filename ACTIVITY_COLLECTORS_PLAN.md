# AWS Activity Collectors Implementation Plan

## Current State

Two activity collectors exist: **login** (`ConsoleLogin`, `UserAuthentication`, `CredentialVerification`) and **session** (`Authenticate`, `Federate`, `Logout`). Both follow the same structural pattern: options type → collector struct with `Init`/`Start`/`Stop` → event mapper → manifest registration.

## Metadata

`stampActivityEventMetadata` is unnecessary in the connector — metadata attachment is mesh-core's responsibility. The connector just needs to emit properly enriched events via `c.Emit(ctx, event)`. The existing `stampActivityEventMetadata` calls in the login and session collectors should be removed. New collectors should not use it.

Resume cursors (`loginResumeCursor`, `sessionResumeCursor`) remain — they extract timestamp/ref from the last-emitted payload for resumption, which is connector-side logic.

## Why `LogoutUser` is Missing

The login collector only watches for authentication events. `LogoutUser` is a valid CloudTrail event for console/IAM user-initiated logouts. The session collector handles SSO `Logout`, but the IAM-side logout is unhandled. This should be added to the login collector since it bookends the `ConsoleLogin` flow.

## CloudTrail Event Reference

Event names sourced from [pkazi/cloudTrailEventNames.list](https://gist.github.com/pkazi/8b5a1374771f6efa5d55b92d8835718c).

---

## Phase 1: Enhance Login/Logout Collector

**Modify** `internal/collectors/activity/login_activity_collector.go`

| CloudTrail Event | SDK Event Type | Status |
|---|---|---|
| `ConsoleLogin` (success) | `LoginSucceeded` | Exists |
| `ConsoleLogin` (failure) | `LoginFailed` | Exists |
| `UserAuthentication` | `LoginSucceeded` | Exists |
| `CredentialVerification` (failure) | `LoginFailed` | Exists |
| **`LogoutUser`** | **`SessionTerminated`** | **Add** |

**Changes required:**

1. Add `"LogoutUser"` to the event name loop in `Start()`.
2. Add a `"LogoutUser"` case in `mapLoginActivityEvent` → emit `SessionTerminated` with reason `"logout"`, session type `"console"`.
3. Add `*events.SessionTerminated` to `loginResumeCursor` switch.
4. Remove `stampActivityEventMetadata` call from `Start()`.
5. Remove `stampActivityEventMetadata` from `common.go` (after session collector is also updated).

---

## Phase 2: Group Lifecycle Activity Collector (new)

**CloudTrail events:**

| CloudTrail Event | SDK Event Type |
|---|---|
| `CreateGroup` | `events.GroupCreated` |
| `DeleteGroup` | `events.GroupRemoved` |

**New files:**

- `internal/collectors/activity/group_activity_collector.go` — collector struct + mapper
- `internal/options/aws_group_activity_collector_options.go` — options with `AWSConnectionOptionsCore` embed

**Modified files:**

- `internal/collectors/activity/common.go` — add `awsGroupActivityLogName` const; add `groupResumeCursor` function
- `internal/options/register.go` — register `AWSGroupActivityCollectorOptions`
- `cmd/main.go` — register `aws_group_activity_collector` feature

**Mapper notes:** Extract group name from `detail.RequestParameters["groupName"]` to populate `Target.Ref` and `Target.DisplayName`. Set `GroupType` to `"IAM"`.

---

## Phase 3: Group Membership Activity Collector (new)

**CloudTrail events:**

| CloudTrail Event | SDK Event Type |
|---|---|
| `AddUserToGroup` | `events.GroupMemberAdded` |
| `RemoveUserFromGroup` | `events.GroupMemberRemoved` |

**New files:**

- `internal/collectors/activity/group_membership_activity_collector.go`
- `internal/options/aws_group_membership_activity_collector_options.go`

**Modified files:** Same pattern as Phase 2 (common.go, register.go, main.go).

**Mapper notes:** Extract `groupName` and `userName` from `detail.RequestParameters`. Populate `GroupRef`/`GroupName` from the group fields, and `Target` from the user being added/removed. The `Actor` is who performed the action (from `userIdentity`).

---

## Phase 4: Role/Entitlement Lifecycle Activity Collector (new)

**CloudTrail events:**

| CloudTrail Event | SDK Event Type | Notes |
|---|---|---|
| `CreateRole` | `AdministrativeActionPerformed` | category: `"role"` |
| `DeleteRole` | `AdministrativeActionPerformed` | category: `"role"` |
| `CreatePolicy` | `AdministrativeActionPerformed` | category: `"policy"` |
| `DeletePolicy` | `AdministrativeActionPerformed` | category: `"policy"` |
| `CreatePermissionSet` | `AdministrativeActionPerformed` | category: `"permission_set"` |
| `DeletePermissionSet` | `AdministrativeActionPerformed` | category: `"permission_set"` |

**Rationale for `AdministrativeActionPerformed`:** The `RoleAssigned`/`RoleRemoved` SDK events model assignment of a role _to a subject_. Creating/deleting the role entity itself is an administrative action — no subject is being granted or denied anything yet.

**New files:**

- `internal/collectors/activity/role_activity_collector.go`
- `internal/options/aws_role_activity_collector_options.go`

**Modified files:** Same pattern as Phase 2 (common.go, register.go, main.go).

**Mapper notes:** Extract role/policy name and ARN from `detail.RequestParameters` and `detail.ResponseElements`. Populate `Target` with the role/policy ARN. Set `Summary` to human-readable text like `"IAM role 'MyRole' created"`.

---

## Phase 5: Role/Entitlement Change Activity Collector (new)

**CloudTrail events:**

| CloudTrail Event | SDK Event Type | Notes |
|---|---|---|
| `AttachRolePolicy` | `PermissionGranted` | Policy attached to role |
| `DetachRolePolicy` | `PermissionRevoked` | Policy detached from role |
| `AttachUserPolicy` | `PermissionGranted` | Policy attached to user |
| `DetachUserPolicy` | `PermissionRevoked` | Policy detached from user |
| `AttachGroupPolicy` | `PermissionGranted` | Policy attached to group |
| `DetachGroupPolicy` | `PermissionRevoked` | Policy detached from group |
| `PutRolePolicy` | `PermissionGranted` | Inline policy set on role |
| `PutUserPolicy` | `PermissionGranted` | Inline policy set on user |
| `PutGroupPolicy` | `PermissionGranted` | Inline policy set on group |
| `DeleteRolePolicy` | `PermissionRevoked` | Inline policy removed from role |
| `DeleteUserPolicy` | `PermissionRevoked` | Inline policy removed from user |
| `DeleteGroupPolicy` | `PermissionRevoked` | Inline policy removed from group |
| `UpdateAssumeRolePolicy` | `PolicyModified` | Trust policy changed |
| `CreatePolicyVersion` | `PolicyModified` | New version of managed policy |

**New files:**

- `internal/collectors/activity/entitlement_activity_collector.go`
- `internal/options/aws_entitlement_activity_collector_options.go`

**Modified files:** Same pattern as Phase 2 (common.go, register.go, main.go).

**Mapper notes:** Extract `policyArn`/`policyName`, `roleName`/`userName`/`groupName` from `detail.RequestParameters`. For attach/detach, the `Target` is the principal receiving the permission; `PermissionRef`/`PermissionName` come from the policy. For `PolicyModified`, the `Target` is the policy itself.

---

## Phase 6: Account Lifecycle Activity Collector (new)

**CloudTrail events:**

| CloudTrail Event | SDK Event Type | Notes |
|---|---|---|
| `CreateUser` | `events.AccountCreated` | IAM user created |
| `DeleteUser` | `events.AccountDeleted` | IAM user deleted |
| `CreateLoginProfile` | `events.AccountCreated` | Console access enabled (optional) |
| `CreateAccount` | `events.AccountCreated` | AWS Organizations account |

**New files:**

- `internal/collectors/activity/account_activity_collector.go`
- `internal/options/aws_account_activity_collector_options.go`

**Modified files:** Same pattern as Phase 2 (common.go, register.go, main.go).

**Mapper notes:** Extract `userName` from `detail.RequestParameters`. Set `AccountType` to `"IAM"` or `"Organization"` depending on the event. `Target` is the user/account being created/deleted. `Actor` is the admin performing the action.

---

## Options Requirements

Each new collector options type needs `GetRequirements()` to declare its dependencies:

- Group/Membership/Account collectors: `[]string{"aws", "cloudtrail", "iam"}`
- Role/Entitlement collectors: `[]string{"aws", "cloudtrail", "iam"}`
- Collectors touching Identity Center: add `"identitycenter"`

---

## Testing

Each collector gets unit tests for its `map*ActivityEvent` function following the existing pattern in `activity_collectors_test.go`. Test both success and skip paths (missing actor, unknown event name).

---

## Implementation Order

| Phase | Collector | Effort | Dependencies |
|---|---|---|---|
| 1 | Login/Logout (enhance) | Small | None |
| 2 | Group lifecycle | Medium | None |
| 3 | Group membership | Medium | Phase 2 patterns |
| 4 | Role/Entitlement lifecycle | Medium | Phase 2 patterns |
| 5 | Role/Entitlement change | Large (14 events) | Phase 4 |
| 6 | Account lifecycle | Medium | Phase 2 patterns |

Phases 2–6 all follow the same structural template. Once Phase 2 is complete, the remaining collectors are largely mechanical.
