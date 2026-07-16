// Package scope resolves an AWS collector's configured scope into concrete
// collection targets. In single-account mode it yields one target using the
// connector's credentials. In organization mode it authenticates to the
// management/delegated account, enumerates AWS Organizations member accounts,
// and STS-assumes a discovery role into each so a single collector can fan out
// across the whole organization. Accounts that cannot be assumed are skipped so
// one bad account never fails the entire run.
package scope

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hydn-co/substrate/enumerators"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/options"
)

// assumeRoleSessionName labels the STS session opened when assuming a member-account role.
const assumeRoleSessionName = "mesh-aws-discovery"

// Target is one (account, region) collection target with ready-to-use credentials.
// In single mode AccountID is empty and Region is the configured primary region.
type Target struct {
	AccountID    string
	AccountName  string
	Region       string
	Credentials  *api.AWSCredentials
	SessionToken string
}

// OrgClient is the subset of the AWS client the resolver needs to enumerate the
// organization and assume member-account roles. *api.Client satisfies it.
type OrgClient interface {
	DescribeOrganization(ctx context.Context) (*api.Organization, error)
	OrganizationAccountEnumerator(ctx context.Context) enumerators.Enumerator[api.Account]
	OrganizationAccountsForParentEnumerator(ctx context.Context, parentID string) enumerators.Enumerator[api.Account]
	OrganizationalUnitsForParentEnumerator(
		ctx context.Context,
		parentID string,
	) enumerators.Enumerator[api.OrganizationalUnit]
	AssumeRole(ctx context.Context, roleArn, sessionName, externalID string) (*api.AssumedCredentials, error)
}

// OrgClientFactory builds an OrgClient for the management/delegated account.
type OrgClientFactory func(creds *api.AWSCredentials, region, sessionToken string) (OrgClient, error)

// LogFunc receives resolver progress/skip messages (defaults to a no-op).
type LogFunc func(level slog.Level, msg string, args ...any)

// Resolver turns scope options into collection targets.
type Resolver struct {
	opts          *options.AWSScopeOptionsCore
	mgmtCreds     *api.AWSCredentials
	newOrgClient  OrgClientFactory
	log           LogFunc
	primaryRegion string
	sessionToken  string
}

// Option customizes a Resolver.
type Option func(*Resolver)

// WithOrgClientFactory overrides how the management OrgClient is constructed (for tests).
func WithOrgClientFactory(factory OrgClientFactory) Option {
	return func(r *Resolver) {
		if factory != nil {
			r.newOrgClient = factory
		}
	}
}

// WithLogger sets the resolver's progress logger.
func WithLogger(log LogFunc) Option {
	return func(r *Resolver) {
		if log != nil {
			r.log = log
		}
	}
}

// NewResolver constructs a Resolver from scope options, the primary region, the
// connector session token (single-mode only), and the management credentials.
func NewResolver(
	scopeOpts *options.AWSScopeOptionsCore,
	primaryRegion, sessionToken string,
	mgmtCreds *api.AWSCredentials,
	opts ...Option,
) *Resolver {
	r := &Resolver{
		opts:          scopeOpts,
		primaryRegion: primaryRegion,
		sessionToken:  sessionToken,
		mgmtCreds:     mgmtCreds,
		newOrgClient:  defaultOrgClientFactory,
		log:           func(slog.Level, string, ...any) {},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func defaultOrgClientFactory(creds *api.AWSCredentials, region, sessionToken string) (OrgClient, error) {
	return api.NewClient(creds, region, sessionToken)
}

// IsOrganizationMode reports whether the resolver fans out across the organization.
func (r *Resolver) IsOrganizationMode() bool {
	return r.opts.IsOrganizationMode()
}

// Resolve returns the collection targets. Pass regional=true for region-scoped
// services (e.g. Secrets Manager) so organization mode expands to one target per
// (account, region); pass false for global services (e.g. IAM).
func (r *Resolver) Resolve(ctx context.Context, regional bool) ([]Target, error) {
	if !r.opts.IsOrganizationMode() {
		return []Target{{
			Region:       r.primaryRegion,
			Credentials:  r.mgmtCreds,
			SessionToken: r.sessionToken,
		}}, nil
	}
	return r.resolveOrganization(ctx, regional)
}

func (r *Resolver) resolveOrganization(ctx context.Context, regional bool) ([]Target, error) {
	mgmt, err := r.newOrgClient(r.mgmtCreds, r.primaryRegion, r.sessionToken)
	if err != nil {
		return nil, fmt.Errorf("create management client: %w", err)
	}

	members, err := r.memberAccounts(ctx, mgmt)
	if err != nil {
		return nil, err
	}

	regions := r.regions(regional)
	targets := make([]Target, 0, len(members)*len(regions))
	for _, member := range members {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		creds, sessionToken, err := r.assume(ctx, mgmt, member)
		if err != nil {
			r.log(slog.LevelWarn, "skipping account: assume role failed",
				"account_id", member.id, "role_arn", member.roleArn, "error", err.Error())
			continue
		}

		for _, region := range regions {
			targets = append(targets, Target{
				AccountID:    member.id,
				AccountName:  member.name,
				Region:       region,
				Credentials:  creds,
				SessionToken: sessionToken,
			})
		}
	}
	return targets, nil
}

// memberAccount is a selected account plus the role to assume in it.
type memberAccount struct {
	id           string
	name         string
	roleArn      string
	isManagement bool
}

func (r *Resolver) memberAccounts(ctx context.Context, mgmt OrgClient) ([]memberAccount, error) {
	if statics := r.opts.GetStaticAccounts(); len(statics) > 0 {
		members := make([]memberAccount, 0, len(statics))
		for _, account := range statics {
			members = append(members, memberAccount{
				id:      strings.TrimSpace(account.AccountID),
				roleArn: strings.TrimSpace(account.RoleArn),
			})
		}
		return members, nil
	}

	masterID := r.managementAccountID(ctx, mgmt)

	accounts, err := r.enumerateAccounts(ctx, mgmt)
	if err != nil {
		return nil, err
	}

	include := toSet(r.opts.GetIncludeAccountIDs())
	exclude := toSet(r.opts.GetExcludeAccountIDs())

	members := make([]memberAccount, 0, len(accounts))
	for _, account := range accounts {
		if !strings.EqualFold(account.Status, api.AccountStatusActive) {
			continue
		}
		if len(include) > 0 && !include[account.ID] {
			continue
		}
		if exclude[account.ID] {
			continue
		}

		isManagement := masterID != "" && account.ID == masterID
		if isManagement && r.opts.GetSkipManagementAccount() {
			continue
		}

		members = append(members, memberAccount{
			id:           account.ID,
			name:         account.Name,
			roleArn:      r.roleArnFor(account.ID),
			isManagement: isManagement,
		})
	}
	return members, nil
}

func (r *Resolver) managementAccountID(ctx context.Context, mgmt OrgClient) string {
	org, err := mgmt.DescribeOrganization(ctx)
	if err != nil {
		r.log(slog.LevelWarn, "could not describe organization; management account treated as a normal member",
			"error", err.Error())
		return ""
	}
	return org.MasterAccountID
}

func (r *Resolver) enumerateAccounts(ctx context.Context, mgmt OrgClient) ([]api.Account, error) {
	ouIDs := r.opts.GetOrganizationalUnitIDs()
	if len(ouIDs) == 0 {
		return collect(mgmt.OrganizationAccountEnumerator(ctx))
	}

	var accounts []api.Account
	seen := map[string]bool{}
	for _, ouID := range ouIDs {
		if err := r.walkOU(ctx, mgmt, strings.TrimSpace(ouID), seen, &accounts); err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

// walkOU collects the accounts directly under parentID and recurses into its
// child OUs so an OU scope includes nested OUs.
func (r *Resolver) walkOU(
	ctx context.Context,
	mgmt OrgClient,
	parentID string,
	seen map[string]bool,
	accounts *[]api.Account,
) error {
	direct, err := collect(mgmt.OrganizationAccountsForParentEnumerator(ctx, parentID))
	if err != nil {
		return err
	}
	for _, account := range direct {
		if !seen[account.ID] {
			seen[account.ID] = true
			*accounts = append(*accounts, account)
		}
	}

	childOUs, err := collect(mgmt.OrganizationalUnitsForParentEnumerator(ctx, parentID))
	if err != nil {
		return err
	}
	for _, ou := range childOUs {
		if err := r.walkOU(ctx, mgmt, ou.ID, seen, accounts); err != nil {
			return err
		}
	}
	return nil
}

func (r *Resolver) assume(
	ctx context.Context,
	mgmt OrgClient,
	member memberAccount,
) (*api.AWSCredentials, string, error) {
	// The management account is where the connector already authenticates, so its
	// credentials are used directly rather than assuming a (possibly absent) role.
	if member.isManagement {
		return r.mgmtCreds, r.sessionToken, nil
	}

	assumed, err := mgmt.AssumeRole(ctx, member.roleArn, assumeRoleSessionName, r.opts.GetExternalID())
	if err != nil {
		return nil, "", err
	}
	creds := &api.AWSCredentials{
		AccessKeyID:     assumed.AccessKeyID,
		SecretAccessKey: assumed.SecretAccessKey,
	}
	return creds, assumed.SessionToken, nil
}

// roleArnFor builds the discovery-role ARN for an account from the configured role name.
func (r *Resolver) roleArnFor(accountID string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, r.opts.GetAssumeRoleName())
}

func (r *Resolver) regions(regional bool) []string {
	if !regional {
		return []string{r.primaryRegion}
	}
	regions := r.opts.GetRegions()
	if len(regions) == 0 {
		return []string{r.primaryRegion}
	}
	return regions
}

// ForEachTarget resolves targets and invokes fn once per target with a typed
// client built from that target's credentials/region. In organization mode a
// client-construction or collection failure for one target is logged and
// skipped (partial-failure tolerance); in single mode errors propagate so
// existing single-account behavior is preserved. Context cancellation always aborts.
func ForEachTarget[T any](
	ctx context.Context,
	r *Resolver,
	regional bool,
	factory func(creds *api.AWSCredentials, region, sessionToken string) (T, error),
	fn func(ctx context.Context, client T, target Target) error,
) error {
	targets, err := r.Resolve(ctx, regional)
	if err != nil {
		return err
	}

	orgMode := r.opts.IsOrganizationMode()
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}

		client, err := factory(target.Credentials, target.Region, target.SessionToken)
		if err != nil {
			if !orgMode {
				return fmt.Errorf("create AWS client: %w", err)
			}
			r.log(slog.LevelWarn, "skipping target: client construction failed",
				"account_id", target.AccountID, "region", target.Region, "error", err.Error())
			continue
		}

		if err := fn(ctx, client, target); err != nil {
			if ctx.Err() != nil || !orgMode {
				return err
			}
			r.log(slog.LevelWarn, "account collection failed; continuing",
				"account_id", target.AccountID, "region", target.Region, "error", err.Error())
			continue
		}
	}
	return nil
}

func collect[T any](enum enumerators.Enumerator[T]) ([]T, error) {
	var items []T
	err := enumerators.ForEach(enum, func(item T) error {
		items = append(items, item)
		return nil
	})
	return items, err
}

func toSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.TrimSpace(value)] = true
	}
	return set
}
