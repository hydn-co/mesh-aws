package collectors

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IAMUserEntityCollector lists IAM users and emits Account entities.
type IAMUserEntityCollector struct {
	ctx *connector.TypedFeatureContext[*options.UsersOptions, *payloads.ActivityResumePayload]
}

// NewIAMUserEntityCollector constructs the collector with the given feature context.
func NewIAMUserEntityCollector(ctx *connector.TypedFeatureContext[*options.UsersOptions, *payloads.ActivityResumePayload]) runner.Feature {
	return &IAMUserEntityCollector{ctx: ctx}
}

func (c *IAMUserEntityCollector) Init(_ context.Context) error { return nil }
func (c *IAMUserEntityCollector) Stop(_ context.Context) error { return nil }

func (c *IAMUserEntityCollector) Start(ctx context.Context) error {
	const name = "iam-user-entity-collector"
	logCollectStart(name)

	creds, err := credentials.Parse(c.ctx.GetCredentials())
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("parse credentials: %w", err)
	}

	client, err := api.New(ctx, creds)
	if err != nil {
		logCollectError(name, err)
		return fmt.Errorf("create AWS client: %w", err)
	}

	count := 0
	paginator := iam.NewListUsersPaginator(client.IAM, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			logCollectError(name, err)
			return fmt.Errorf("list IAM users: %w", err)
		}

		for _, u := range page.Users {
			account := entities.NewAccount()
			account.AccountRef = aws.ToString(u.UserName)
			account.Name = aws.ToString(u.UserName)
			account.DisplayName = aws.ToString(u.UserName)
			account.AccountType = types.AccountTypeUser
			account.Enabled = true
			if u.CreateDate != nil {
				account.CreatedAt = u.CreateDate
			}

			if err := c.ctx.Emit(ctx, account); err != nil {
				logCollectError(name, err)
				return fmt.Errorf("emit account: %w", err)
			}
			count++
		}
	}

	logCollectDone(name, count)
	return nil
}
