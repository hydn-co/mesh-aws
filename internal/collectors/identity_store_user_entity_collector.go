package collectors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/helpers"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/connectorutil"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IdentityStoreUserEntityCollector lists users from AWS Identity Store.
type IdentityStoreUserEntityCollector struct {
	*connector.TypedFeatureContext[*options.IdentityStoreUsersOptions, *connector.NoPayload]
	client      *api.Client
	initialized bool
}

// NewIdentityStoreUserEntityCollector constructs the collector with the given feature context.
func NewIdentityStoreUserEntityCollector(
	ctx *connector.TypedFeatureContext[*options.IdentityStoreUsersOptions, *connector.NoPayload],
) runner.Feature {
	return &IdentityStoreUserEntityCollector{TypedFeatureContext: ctx}
}

func (c *IdentityStoreUserEntityCollector) Init(ctx context.Context) error {
	options := c.GetOptions()
	if options == nil || options.IdentityStoreID == "" {
		return fmt.Errorf("identity_store_id is required")
	}

	creds, err := credentials.Parse(c.GetCredentials())
	if err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.NewClient(creds)
	if err != nil {
		return fmt.Errorf("create AWS client: %w", err)
	}

	c.client = client
	c.initialized = true
	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"initialized Identity Store user collector",
		"identity_store_id",
		options.IdentityStoreID,
	)
	return nil
}

func (c *IdentityStoreUserEntityCollector) Start(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	options := c.GetOptions()
	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"starting Identity Store user collection",
		"identity_store_id",
		options.IdentityStoreID,
	)

	count := 0
	var nextToken string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		users, token, err := c.client.ListIdentityStoreUsers(ctx, options.IdentityStoreID, nextToken)
		if err != nil {
			connectorutil.LogFeature(
				ctx,
				c.TypedFeatureContext,
				slog.LevelError,
				"failed to list Identity Store users",
				"error",
				err,
			)
			return fmt.Errorf("list Identity Store users: %w", err)
		}

		for _, user := range users {
			account := entities.NewAccount()
			account.AccountRef = user.UserID
			account.AccountType = types.AccountTypeUser
			account.Name = firstNonEmpty(user.UserName, user.UserID)
			account.DisplayName = firstNonEmpty(user.DisplayName, user.UserName)
			account.FirstName = user.GivenName
			account.MiddleName = user.MiddleName
			account.LastName = user.FamilyName
			account.Description = user.UserID
			account.Enabled = user.Active

			for _, email := range user.Emails {
				typedEmail := &types.Email{Address: email.Value}
				if email.Primary && account.PrimaryEmail == nil {
					account.PrimaryEmail = typedEmail
				} else {
					account.AlternateEmails = append(account.AlternateEmails, typedEmail)
				}
			}
			for _, phone := range user.PhoneNumbers {
				typedPhone := &types.Phone{Number: phone.Value}
				if phone.Primary && account.PrimaryPhone == nil {
					account.PrimaryPhone = typedPhone
				} else {
					account.AlternatePhones = append(account.AlternatePhones, typedPhone)
				}
			}

			if err := c.Emit(ctx, account); err != nil {
				connectorutil.LogFeature(
					ctx,
					c.TypedFeatureContext,
					slog.LevelError,
					"failed to emit Identity Store user",
					"account_ref",
					account.AccountRef,
					"error",
					err,
				)
				return fmt.Errorf("emit Identity Store user: %w", err)
			}
			count++
		}

		if token == "" {
			break
		}
		nextToken = token
	}

	connectorutil.LogFeature(
		ctx,
		c.TypedFeatureContext,
		slog.LevelInfo,
		"finished Identity Store user collection",
		"count",
		count,
	)
	return nil
}

func (c *IdentityStoreUserEntityCollector) Stop(ctx context.Context) error {
	if err := helpers.CheckInitialized(c.initialized); err != nil {
		return err
	}

	c.client = nil
	c.initialized = false
	connectorutil.LogFeature(ctx, c.TypedFeatureContext, slog.LevelInfo, "stopped Identity Store user collector")
	return nil
}
