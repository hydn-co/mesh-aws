#!/usr/bin/env python3
"""Deploy the Hydden discovery role across an AWS Organization via CloudFormation StackSets.

This is a cross-platform helper (Python 3 + boto3) that the mesh-aws connector's
organization mode relies on: it creates a service-managed StackSet from
``hydden-discovery-role.yaml`` and rolls the role out to every member account in the
chosen organizational units, with auto-deployment so accounts added later receive it
automatically. An optional exclude list keeps the role out of specific accounts via the
StackSet ``AccountFilterType: DIFFERENCE`` deployment filter.

Prerequisites:
  * Python 3.9+ and boto3 (``pip install boto3``).
  * Credentials for the Organization's management or delegated-admin account.
  * Trusted access for CloudFormation StackSets enabled for the Organization
    (pass ``--activate-org-access`` once, or enable it in the console).

Examples:
  # Deploy to the whole organization (org root), trusting the deploying identity:
  python3 deploy_discovery_role.py

  # Specific OUs, an external id, and an exclude list, as a dry run first:
  python3 deploy_discovery_role.py \\
      --ou-ids ou-root-workloads ou-root-sandbox \\
      --external-id hydden-prod \\
      --exclude-accounts 111111111111 222222222222 \\
      --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:  # pragma: no cover - dependency guidance
    sys.exit("boto3 is required: install it with `pip install boto3`.")

DEFAULT_TEMPLATE = Path(__file__).resolve().parent / "hydden-discovery-role.yaml"
DEFAULT_ROLE_NAME = "HyddenDiscoveryRole"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy the Hydden discovery role org-wide via a CloudFormation StackSet.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--collector-arn",
        help="IAM user/role ARN that owns the connector's access key/secret (the principal "
        "that calls sts:AssumeRole). Defaults to the identity running this script "
        "(aws sts get-caller-identity). Pass the account root ARN to trust the whole account.",
    )
    parser.add_argument("--role-name", default=DEFAULT_ROLE_NAME,
                        help="Discovery role name; must match the connector's assume_role_name.")
    parser.add_argument("--external-id", default="",
                        help="Optional sts:ExternalId; must match the connector's external_id.")
    parser.add_argument("--ou-ids", nargs="*", default=None,
                        help="Organizational unit IDs to deploy into. Defaults to the org root.")
    parser.add_argument("--exclude-accounts", nargs="*", default=None,
                        help="Account IDs to skip (StackSet AccountFilterType=DIFFERENCE). "
                        "Should mirror the connector's exclude_account_ids.")
    parser.add_argument("--region", default=None,
                        help="Region for the StackSet and its stack instances (IAM is global; one "
                        "suffices). Defaults to your AWS config (AWS_REGION / AWS_DEFAULT_REGION / "
                        "profile region); required if none is configured.")
    parser.add_argument("--stack-set-name", default=None,
                        help="Name for the CloudFormation StackSet (the container that manages the "
                        "role's per-account stacks). Defaults to --role-name.")
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE,
                        help="Path to the discovery-role CloudFormation template.")
    parser.add_argument("--activate-org-access", action="store_true",
                        help="Enable trusted access for CloudFormation StackSets first.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the planned API calls without making any changes.")
    return parser.parse_args(argv)


def resolve_collector_arn(session: "boto3.Session", explicit: str | None, dry_run: bool) -> str:
    if explicit:
        return explicit
    if dry_run:
        # Avoid an AWS call (and the credentials it needs) during a preview.
        return "(deploying identity, resolved via sts:GetCallerIdentity at deploy time)"
    arn = session.client("sts").get_caller_identity()["Arn"]
    print(f"--collector-arn not set; defaulting to the deploying identity: {arn}")
    print("  Pass --collector-arn explicitly if the connector uses a different IAM user.")
    return arn


def resolve_ou_ids(session: "boto3.Session", explicit: list[str] | None, dry_run: bool) -> list[str]:
    if explicit:
        return explicit
    if dry_run:
        # Avoid an AWS call (and the credentials it needs) during a preview.
        return ["(organization root, resolved via organizations:ListRoots at deploy time)"]
    roots = session.client("organizations").list_roots()["Roots"]
    ou_ids = [root["Id"] for root in roots]
    print(f"--ou-ids not set; defaulting to the organization root(s): {', '.join(ou_ids)}")
    return ou_ids


def stack_set_exists(cfn, name: str) -> bool:
    try:
        cfn.describe_stack_set(StackSetName=name, CallAs="SELF")
        return True
    except ClientError as error:
        if error.response["Error"]["Code"] in ("StackSetNotFoundException", "NotFound"):
            return False
        raise


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    template_body = args.template.read_text(encoding="utf-8")

    # Resolve the region from --region, falling back to the AWS config (env /
    # profile). boto3 still needs a region to build clients even though IAM is
    # global, so fail with a clear message rather than a raw NoRegionError.
    session = boto3.Session(region_name=args.region)
    region = session.region_name
    if not region:
        sys.exit(
            "error: no AWS region configured. Pass --region <region> (e.g. --region us-east-1), "
            "or set AWS_REGION / AWS_DEFAULT_REGION, or set a default region in your AWS profile."
        )

    # The StackSet name defaults to the role name so they never drift.
    stack_set_name = args.stack_set_name or args.role_name

    cfn = session.client("cloudformation")

    collector_arn = resolve_collector_arn(session, args.collector_arn, args.dry_run)
    ou_ids = resolve_ou_ids(session, args.ou_ids, args.dry_run)
    excludes = args.exclude_accounts or []

    parameters = [
        {"ParameterKey": "CollectorPrincipalArn", "ParameterValue": collector_arn},
        {"ParameterKey": "DiscoveryRoleName", "ParameterValue": args.role_name},
        {"ParameterKey": "ExternalId", "ParameterValue": args.external_id},
    ]

    deployment_targets: dict = {"OrganizationalUnitIds": ou_ids}
    if excludes:
        deployment_targets["AccountFilterType"] = "DIFFERENCE"
        deployment_targets["Accounts"] = excludes

    exists = False if args.dry_run else stack_set_exists(cfn, stack_set_name)
    action = "update" if exists else "create"

    print("\nPlanned deployment:")
    print(f"  StackSet         : {stack_set_name} ({action})")
    print(f"  Role name        : {args.role_name}")
    print(f"  Collector ARN    : {collector_arn}")
    print(f"  External ID      : {args.external_id or '(none)'}")
    print(f"  OUs              : {', '.join(ou_ids)}")
    print(f"  Excluded accounts: {', '.join(excludes) if excludes else '(none)'}")
    print(f"  Region           : {region}")

    if args.dry_run:
        print("\n--dry-run: no changes made.")
        return 0

    if args.activate_org_access:
        print("\nEnabling trusted access for CloudFormation StackSets ...")
        cfn.activate_organizations_access()

    stack_set_kwargs = dict(
        StackSetName=stack_set_name,
        Description="Hydden mesh-aws cross-account discovery role.",
        TemplateBody=template_body,
        Parameters=parameters,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        PermissionModel="SERVICE_MANAGED",
        AutoDeployment={"Enabled": True, "RetainStacksOnAccountRemoval": False},
    )
    if exists:
        print(f"\nUpdating existing StackSet {stack_set_name} ...")
        cfn.update_stack_set(**stack_set_kwargs)
    else:
        print(f"\nCreating StackSet {stack_set_name} ...")
        cfn.create_stack_set(**stack_set_kwargs)

    print("Creating stack instances across the organization ...")
    try:
        response = cfn.create_stack_instances(
            StackSetName=stack_set_name,
            DeploymentTargets=deployment_targets,
            Regions=[region],
            OperationPreferences={
                "RegionConcurrencyType": "PARALLEL",
                "MaxConcurrentPercentage": 100,
                "FailureTolerancePercentage": 10,
            },
        )
        print(f"Started StackSet operation {response['OperationId']}.")
        print("Track progress with: aws cloudformation list-stack-set-operations "
              f"--stack-set-name {stack_set_name}")
    except ClientError as error:
        # Re-running over accounts that already have instances is expected after the
        # first deploy; auto-deployment handles newly added accounts automatically.
        print(f"create_stack_instances reported: {error}", file=sys.stderr)
        print("If instances already exist this is expected; new accounts are covered by "
              "auto-deployment.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NoCredentialsError:
        sys.exit(
            "error: unable to locate AWS credentials. Configure credentials for the "
            "management/delegated-admin account (set AWS_PROFILE, export "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, or run `aws configure`). "
            "Tip: add --dry-run to preview the plan without AWS access."
        )
