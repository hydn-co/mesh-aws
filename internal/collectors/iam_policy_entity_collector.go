package collectors

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hydn-co/mesh-aws/internal/api"
	"github.com/hydn-co/mesh-aws/internal/credentials"
	"github.com/hydn-co/mesh-aws/internal/options"
	"github.com/hydn-co/mesh-aws/internal/payloads"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/entities"
	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
	"github.com/hydn-co/mesh-sdk/pkg/connector"
	"github.com/hydn-co/mesh-sdk/pkg/runner"
)

// IAMPolicyEntityCollector lists customer-managed IAM policies and emits Policy entities.
type IAMPolicyEntityCollector struct {
	ctx *connector.TypedFeatureContext[*options.PoliciesOptions, *payloads.ActivityResumePayload]
}

// NewIAMPolicyEntityCollector constructs the collector with the given feature context.
func NewIAMPolicyEntityCollector(ctx *connector.TypedFeatureContext[*options.PoliciesOptions, *payloads.ActivityResumePayload]) runner.Feature {
	return &IAMPolicyEntityCollector{ctx: ctx}
}

func (c *IAMPolicyEntityCollector) Init(_ context.Context) error { return nil }
func (c *IAMPolicyEntityCollector) Stop(_ context.Context) error { return nil }

func (c *IAMPolicyEntityCollector) Start(ctx context.Context) error {
	const name = "iam-policy-entity-collector"
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
	paginator := iam.NewListPoliciesPaginator(client.IAM, &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			logCollectError(name, err)
			return fmt.Errorf("list IAM policies: %w", err)
		}

		for _, p := range page.Policies {
			policy := entities.NewPolicy()
			policy.PolicyRef = aws.ToString(p.PolicyName)
			policy.Name = aws.ToString(p.PolicyName)
			policy.Description = aws.ToString(p.Description)
			policy.PolicyType = types.PolicyTypeAuthorization
			policy.State = "enabled"

			if err := c.ctx.Emit(ctx, policy); err != nil {
				logCollectError(name, err)
				return fmt.Errorf("emit policy: %w", err)
			}
			count++
		}
	}

	logCollectDone(name, count)
	return nil
}
