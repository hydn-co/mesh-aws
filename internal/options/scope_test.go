package options

import "testing"

func TestShouldDefaultToSingleModeWhenModeEmpty(t *testing.T) {
	opts := &AWSScopeOptionsCore{}
	if got := opts.GetMode(); got != ModeSingle {
		t.Fatalf("GetMode() = %q, want %q", got, ModeSingle)
	}
	if opts.IsOrganizationMode() {
		t.Fatal("IsOrganizationMode() = true, want false for empty mode")
	}
}

func TestShouldReportOrganizationModeWhenConfigured(t *testing.T) {
	opts := &AWSScopeOptionsCore{Mode: "Organization"}
	if !opts.IsOrganizationMode() {
		t.Fatal("IsOrganizationMode() = false, want true (mode should be case-insensitive)")
	}
}

func TestShouldPassValidationWhenSingleMode(t *testing.T) {
	opts := &AWSScopeOptionsCore{Mode: ModeSingle}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestShouldRequireAssumeRoleNameWhenOrganizationModeWithoutStaticAccounts(t *testing.T) {
	opts := &AWSScopeOptionsCore{Mode: ModeOrganization}
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for organization mode without assume_role_name")
	}
}

func TestShouldPassValidationWhenOrganizationModeWithAssumeRoleName(t *testing.T) {
	opts := &AWSScopeOptionsCore{Mode: ModeOrganization, AssumeRoleName: "HyddenDiscoveryRole"}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestShouldPassValidationWhenStaticAccountsProvided(t *testing.T) {
	opts := &AWSScopeOptionsCore{
		Mode: ModeOrganization,
		StaticAccounts: []StaticAccount{
			{AccountID: "123456789012", RoleArn: "arn:aws:iam::123456789012:role/Custom"},
		},
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestShouldRejectStaticAccountMissingRoleArn(t *testing.T) {
	opts := &AWSScopeOptionsCore{
		Mode:           ModeOrganization,
		StaticAccounts: []StaticAccount{{AccountID: "123456789012"}},
	}
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for static account missing role_arn")
	}
}

func TestShouldRejectUnknownMode(t *testing.T) {
	opts := &AWSScopeOptionsCore{Mode: "bogus"}
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() = nil, want error for unknown mode")
	}
}
