# mesh-aws

AWS mesh connector — collects IAM users, groups, roles, policies and CloudTrail activity.

## Repository Structure

```
cmd/            Entry point (main.go)
internal/
  api/          AWS SDK v2 client wrapper
  actions/      Action feature implementations
  collectors/   Collector feature implementations
  credentials/  AWS credential parsing
  options/      Feature option types
  payloads/     Action payload types
.github/
  workflows/    CI, release and version workflows
```

## Development Commands

```bash
# Build
go build ./...

# Vet
go vet ./...

# Test
go test ./...

# Generate manifest
go run ./cmd -describe

# List features
go run ./cmd -list
```

## Features

| Name | Type | Description |
|---|---|---|
| collect-users | collector | Lists IAM users → Account entities |
| collect-groups | collector | Lists IAM groups → Group entities |
| collect-roles | collector | Lists IAM roles → Role entities |
| collect-policies | collector | Lists customer-managed IAM policies → Policy entities |
| collect-activity | collector | Collects CloudTrail ConsoleLogin events → login activity |
| disable-user | action | Disables IAM user (login profile, access keys, MFA) |
| add-user-to-group | action | Adds IAM user to a group |
| remove-user-from-group | action | Removes IAM user from a group |

## Credentials

The connector expects AWS credentials as JSON:

```json
{
  "access_key_id": "AKIA...",
  "secret_access_key": "...",
  "region": "us-east-1",
  "session_token": ""
}
```
