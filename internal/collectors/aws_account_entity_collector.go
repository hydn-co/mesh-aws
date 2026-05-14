package collectors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fgrzl/enumerators"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// AWSAccountEntityCollector collects AWS account-related entities and membership links.
type AWSAccountEntityCollector struct {
	*connector.TypedFeatureContext[*options.AWSAccountEntityCollectorOptions, *connector.NoPayload]
	client *api.Client
	state  connectorutil.FeatureState
}

// NewAWSAccountEntityCollector constructs the collector with the given feature context.
func NewAWSAccountEntityCollector(
	ctx *connector.TypedFeatureContext[*options.AWSAccountEntityCollectorOptions, *connector.NoPayload],
) runner.Feature {
	return &AWSAccountEntityCollector{TypedFeatureContext: ctx}
}

func (c *AWSAccountEntityCollector) Init(ctx context.Context) error {
	opts := c.GetOptions()
	if err := connectorutil.Validate(opts, "feature options"); err != nil {
		return err
	}

	creds, err := credentials.Parse(c.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds, opts.GetRegion(), opts.GetSessionToken())
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.state.MarkReady()
	return nil
}

func (c *AWSAccountEntityCollector) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.state.RequireReady(); err != nil {
		return err
	}

	opts := c.GetOptions()
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Starting AWS account entity collector")

	accountsEmitted := 0
	membershipsEmitted := 0

	if err := c.emitIAMAccountsAndMemberships(ctx, &accountsEmitted, &membershipsEmitted); err != nil {
		return err
	}

	if identityStoreID := opts.GetIdentityStoreID(); identityStoreID != "" {
		if err := c.emitIdentityStoreAccountsAndMemberships(
			ctx,
			identityStoreID,
			&accountsEmitted,
			&membershipsEmitted,
		); err != nil {
			return err
		}
	}

	if err := c.emitManagementAccount(ctx, &accountsEmitted); err != nil {
		return err
	}

	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "Finished AWS account entity collector",
		"accounts_emitted", accountsEmitted,
		"group_memberships_emitted", membershipsEmitted,
	)
	return nil
}

func (c *AWSAccountEntityCollector) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.state.Reset()
	c.client = nil
	return nil
}

func (c *AWSAccountEntityCollector) emitIAMAccountsAndMemberships(
	ctx context.Context,
	accountsEmitted *int,
	membershipsEmitted *int,
) error {
	userEnum := c.client.IAMUserEnumerator(ctx)
	if err := enumerators.ForEach(userEnum, func(user api.IAMUser) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		account := entities.NewAccount()
		account.AccountRef = user.UserID
		account.Name = user.UserName
		account.Description = user.Arn
		if !user.CreateDate.IsZero() {
			account.CreatedAt = &user.CreateDate
		}

		if err := c.Emit(ctx, account); err != nil {
			return fmt.Errorf("emit IAM user %s: %w", user.UserID, err)
		}
		(*accountsEmitted)++

		groupEnum := c.client.IAMGroupsForUserEnumerator(ctx, user.UserName)
		if err := enumerators.ForEach(groupEnum, func(group api.IAMGroup) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			member := entities.NewGroupMember()
			member.GroupRef = group.GroupID
			member.AccountRef = user.UserID
			if err := c.Emit(ctx, member); err != nil {
				return fmt.Errorf("emit IAM group membership %s/%s: %w", group.GroupID, user.UserID, err)
			}
			(*membershipsEmitted)++
			return nil
		}); err != nil {
			return fmt.Errorf("enumerate IAM groups for user %s: %w", user.UserName, err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("enumerate IAM users: %w", err)
	}

	return nil
}

func (c *AWSAccountEntityCollector) emitIdentityStoreAccountsAndMemberships(
	ctx context.Context,
	identityStoreID string,
	accountsEmitted *int,
	membershipsEmitted *int,
) error {
	userEnum := c.client.IdentityStoreUserEnumerator(ctx, identityStoreID)
	if err := enumerators.ForEach(userEnum, func(user api.IdentityStoreUser) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		account := entities.NewAccount()
		account.AccountRef = user.UserID
		account.Name = user.UserName
		account.DisplayName = user.DisplayName
		account.FirstName = user.GivenName
		account.MiddleName = user.MiddleName
		account.LastName = user.FamilyName
		account.Description = user.UserID
		account.Enabled = user.Active
		if !user.CreatedAt.IsZero() {
			account.CreatedAt = &user.CreatedAt
		}

		if email := choosePrimaryEmail(user.Emails); email != nil {
			account.PrimaryEmail = email.primary
			account.AlternateEmails = email.alternates
		}
		if phone := choosePrimaryPhone(user.PhoneNumbers); phone != nil {
			account.PrimaryPhone = phone.primary
			account.AlternatePhones = phone.alternates
		}

		if err := c.Emit(ctx, account); err != nil {
			return fmt.Errorf("emit Identity Store user %s: %w", user.UserID, err)
		}
		(*accountsEmitted)++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate Identity Store users: %w", err)
	}

	groupEnum := c.client.IdentityStoreGroupEnumerator(ctx, identityStoreID)
	if err := enumerators.ForEach(groupEnum, func(group api.IdentityStoreGroup) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		membershipEnum := c.client.IdentityStoreGroupMembershipEnumerator(ctx, identityStoreID, group.GroupID)
		if err := enumerators.ForEach(membershipEnum, func(membership api.IdentityStoreGroupMembership) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			member := entities.NewGroupMember()
			member.GroupRef = membership.GroupID
			member.AccountRef = membership.MemberUserID
			if err := c.Emit(ctx, member); err != nil {
				return fmt.Errorf(
					"emit Identity Store group membership %s/%s: %w",
					membership.GroupID,
					membership.MemberUserID,
					err,
				)
			}
			(*membershipsEmitted)++
			return nil
		}); err != nil {
			return fmt.Errorf("enumerate Identity Store memberships for group %s: %w", group.GroupID, err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("enumerate Identity Store groups: %w", err)
	}

	return nil
}

func (c *AWSAccountEntityCollector) emitManagementAccount(ctx context.Context, accountsEmitted *int) error {
	organization, err := c.client.DescribeOrganization(ctx)
	if err != nil {
		return fmt.Errorf("describe organization: %w", err)
	}

	account := entities.NewAccount()
	account.AccountRef = organization.MasterAccountID
	account.Name = organization.MasterAccountID
	account.DisplayName = organization.MasterAccountEmail
	account.Description = organization.MasterAccountArn
	if organization.MasterAccountEmail != "" {
		account.PrimaryEmail = &types.Email{Address: organization.MasterAccountEmail}
	}

	if err := c.Emit(ctx, account); err != nil {
		return fmt.Errorf("emit management account %s: %w", organization.MasterAccountID, err)
	}
	(*accountsEmitted)++
	return nil
}

type emailSet struct {
	primary    *types.Email
	alternates []*types.Email
}

func choosePrimaryEmail(emails []api.IdentityStoreEmail) *emailSet {
	if len(emails) == 0 {
		return nil
	}

	result := &emailSet{}
	for _, email := range emails {
		typedEmail := &types.Email{Address: email.Value}
		if email.Primary && result.primary == nil {
			result.primary = typedEmail
			continue
		}
		result.alternates = append(result.alternates, typedEmail)
	}
	return result
}

type phoneSet struct {
	primary    *types.Phone
	alternates []*types.Phone
}

func choosePrimaryPhone(phones []api.IdentityStorePhoneNumber) *phoneSet {
	if len(phones) == 0 {
		return nil
	}

	result := &phoneSet{}
	for _, phone := range phones {
		typedPhone := &types.Phone{Number: phone.Value}
		if phone.Primary && result.primary == nil {
			result.primary = typedPhone
			continue
		}
		result.alternates = append(result.alternates, typedPhone)
	}
	return result
}
