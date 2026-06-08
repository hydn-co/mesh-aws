package options

import (
	"fmt"
	"strings"
)

// Collection modes for AWS data sources.
const (
	// ModeSingle collects from the single account the credentials belong to.
	ModeSingle = "single"
	// ModeOrganization enumerates AWS Organizations member accounts and assumes a
	// discovery role into each, fanning collection out across the organization.
	ModeOrganization = "organization"
)

// StaticAccount explicitly names a member account and the role to assume in it,
// bypassing AWS Organizations enumeration for customers who do not grant the
// collector organizations:ListAccounts.
type StaticAccount struct {
	AccountID string `json:"account_id" title:"Account ID" description:"Twelve-digit AWS member account ID."            binding:"required"`
	RoleArn   string `json:"role_arn"   title:"Role ARN"   description:"ARN of the role to STS-assume in this account." binding:"required"`
}

// AWSScopeOptionsCore configures whether a collector runs against a single account
// or fans out across an AWS Organization. It is embedded by every collector's
// options alongside AWSConnectionOptionsCore. Mode-dependent fields are validated
// here; the resolver in internal/scope consumes these values at collection time.
type AWSScopeOptionsCore struct {
	Mode                  string          `json:"mode"                              title:"Collection Mode"         description:"Whether the connector collects from a single AWS account or fans out across an AWS Organization."                                                                                 binding:"required" enum:"single,organization"`
	AssumeRoleName        string          `json:"assume_role_name,omitempty"        title:"Assume Role Name"        description:"Name of the cross-account discovery role to STS-assume in each member account (e.g. HyddenDiscoveryRole). Required in organization mode unless static accounts supply role ARNs."                                               x-enabled-by:"mode:organization"`
	ExternalID            string          `json:"external_id,omitempty"             title:"External ID"             description:"Optional sts:ExternalId required by the member-account role's trust policy."                                                                                                                                                    x-enabled-by:"mode:organization"`
	IncludeAccountIDs     []string        `json:"include_account_ids,omitempty"     title:"Include Account IDs"     description:"If set, only these member account IDs are collected."                                                                                                                                                                           x-enabled-by:"mode:organization"`
	ExcludeAccountIDs     []string        `json:"exclude_account_ids,omitempty"     title:"Exclude Account IDs"     description:"Member account IDs to skip during organization collection."                                                                                                                                                                     x-enabled-by:"mode:organization"`
	OrganizationalUnitIDs []string        `json:"organizational_unit_ids,omitempty" title:"Organizational Unit IDs" description:"If set, limits collection to accounts within these AWS Organizations OUs (and their child OUs)."                                                                                                                                x-enabled-by:"mode:organization"`
	StaticAccounts        []StaticAccount `json:"static_accounts,omitempty"         title:"Static Accounts"         description:"Explicit member account ID + role ARN entries that bypass AWS Organizations enumeration."                                                                                                                                       x-enabled-by:"mode:organization"`
	Regions               []string        `json:"regions,omitempty"                 title:"Regions"                 description:"Regions to scan for regional services (e.g. Secrets Manager) during organization collection. Defaults to the primary Region when empty."                                                                                        x-enabled-by:"mode:organization"`
	SkipManagementAccount bool            `json:"skip_management_account,omitempty" title:"Skip Management Account" description:"Exclude the management/delegated account from per-account collection."                                                                                                                                                          x-enabled-by:"mode:organization"`
}

// GetMode returns the normalized collection mode, defaulting to single.
func (o *AWSScopeOptionsCore) GetMode() string {
	if o == nil {
		return ModeSingle
	}
	mode := strings.ToLower(strings.TrimSpace(o.Mode))
	if mode == "" {
		return ModeSingle
	}
	return mode
}

// IsOrganizationMode reports whether the collector should fan out across the organization.
func (o *AWSScopeOptionsCore) IsOrganizationMode() bool {
	return o.GetMode() == ModeOrganization
}

// GetAssumeRoleName returns the trimmed cross-account discovery role name.
func (o *AWSScopeOptionsCore) GetAssumeRoleName() string {
	if o == nil {
		return ""
	}
	return strings.TrimSpace(o.AssumeRoleName)
}

// GetExternalID returns the trimmed sts:ExternalId, if any.
func (o *AWSScopeOptionsCore) GetExternalID() string {
	if o == nil {
		return ""
	}
	return strings.TrimSpace(o.ExternalID)
}

// GetIncludeAccountIDs returns the account-ID allowlist.
func (o *AWSScopeOptionsCore) GetIncludeAccountIDs() []string {
	if o == nil {
		return nil
	}
	return o.IncludeAccountIDs
}

// GetExcludeAccountIDs returns the account-ID denylist.
func (o *AWSScopeOptionsCore) GetExcludeAccountIDs() []string {
	if o == nil {
		return nil
	}
	return o.ExcludeAccountIDs
}

// GetOrganizationalUnitIDs returns the OU scope, if any.
func (o *AWSScopeOptionsCore) GetOrganizationalUnitIDs() []string {
	if o == nil {
		return nil
	}
	return o.OrganizationalUnitIDs
}

// GetSkipManagementAccount reports whether to exclude the management account.
func (o *AWSScopeOptionsCore) GetSkipManagementAccount() bool {
	if o == nil {
		return false
	}
	return o.SkipManagementAccount
}

// GetStaticAccounts returns the explicit member-account override list.
func (o *AWSScopeOptionsCore) GetStaticAccounts() []StaticAccount {
	if o == nil {
		return nil
	}
	return o.StaticAccounts
}

// GetRegions returns the configured regional-service scan regions.
func (o *AWSScopeOptionsCore) GetRegions() []string {
	if o == nil {
		return nil
	}
	return o.Regions
}

// Validate checks mode-dependent invariants. Single mode (the default) imposes no
// extra requirements, preserving backward compatibility.
func (o *AWSScopeOptionsCore) Validate() error {
	if o == nil {
		return nil
	}

	switch o.GetMode() {
	case ModeSingle:
		return nil
	case ModeOrganization:
		return o.validateOrganization()
	default:
		return fmt.Errorf("mode must be %q or %q", ModeSingle, ModeOrganization)
	}
}

func (o *AWSScopeOptionsCore) validateOrganization() error {
	if len(o.StaticAccounts) > 0 {
		for i, account := range o.StaticAccounts {
			if strings.TrimSpace(account.AccountID) == "" {
				return fmt.Errorf("static_accounts[%d].account_id is required", i)
			}
			if strings.TrimSpace(account.RoleArn) == "" {
				return fmt.Errorf("static_accounts[%d].role_arn is required", i)
			}
		}
		return nil
	}

	if o.GetAssumeRoleName() == "" {
		return fmt.Errorf("assume_role_name is required in organization mode unless static_accounts are provided")
	}
	return nil
}
