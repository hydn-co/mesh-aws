package api

import (
	"context"
	"encoding/json"
	"fmt"
)

const organizationsDescribeOrganizationTarget = "AWSOrganizationsV20161128.DescribeOrganization"

// Organization represents the management account details returned by AWS Organizations.
type Organization struct {
	MasterAccountID    string
	MasterAccountArn   string
	MasterAccountEmail string
}

type organizationsDescribeOrganizationResponse struct {
	Organization organizationsOrganizationJSON `json:"Organization"`
}

type organizationsOrganizationJSON struct {
	MasterAccountID    string `json:"MasterAccountId"`
	MasterAccountArn   string `json:"MasterAccountArn"`
	MasterAccountEmail string `json:"MasterAccountEmail"`
}

// DescribeOrganization returns the current organization's management account details.
func (c *Client) DescribeOrganization(ctx context.Context) (*Organization, error) {
	responseBody, err := c.organizationsPost(ctx, organizationsDescribeOrganizationTarget, []byte("{}"))
	if err != nil {
		return nil, fmt.Errorf("describe organization: %w", err)
	}

	var response organizationsDescribeOrganizationResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("parse describe organization response: %w", err)
	}

	return &Organization{
		MasterAccountID:    response.Organization.MasterAccountID,
		MasterAccountArn:   response.Organization.MasterAccountArn,
		MasterAccountEmail: response.Organization.MasterAccountEmail,
	}, nil
}
