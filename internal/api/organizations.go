package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	organizationsDescribeOrganizationTarget       = "AWSOrganizationsV20161128.DescribeOrganization"
	organizationsListAccountsTarget               = "AWSOrganizationsV20161128.ListAccounts"
	organizationsListAccountsForParentTarget      = "AWSOrganizationsV20161128.ListAccountsForParent"
	organizationsListRootsTarget                  = "AWSOrganizationsV20161128.ListRoots"
	organizationsListOrganizationalUnitsForParent = "AWSOrganizationsV20161128.ListOrganizationalUnitsForParent"
)

// AccountStatusActive is the AWS Organizations status of a fully usable member account.
const AccountStatusActive = "ACTIVE"

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

// ---- Member account & OU enumeration ----------------------------------------

// Account represents a member account returned by AWS Organizations.
type Account struct {
	JoinedTimestamp time.Time
	ID              string
	Arn             string
	Email           string
	Name            string
	Status          string
}

// OrganizationalUnit represents a root or organizational unit in the Organizations tree.
type OrganizationalUnit struct {
	ID   string
	Arn  string
	Name string
}

type organizationsAccountJSON struct {
	ID              string  `json:"Id"`
	Arn             string  `json:"Arn"`
	Email           string  `json:"Email"`
	Name            string  `json:"Name"`
	Status          string  `json:"Status"`
	JoinedTimestamp float64 `json:"JoinedTimestamp"`
}

func (a organizationsAccountJSON) toAccount() Account {
	account := Account{
		ID:     a.ID,
		Arn:    a.Arn,
		Email:  a.Email,
		Name:   a.Name,
		Status: a.Status,
	}
	if a.JoinedTimestamp > 0 {
		account.JoinedTimestamp = time.Unix(int64(a.JoinedTimestamp), 0).UTC()
	}
	return account
}

type organizationsOUJSON struct {
	ID   string `json:"Id"`
	Arn  string `json:"Arn"`
	Name string `json:"Name"`
}

func (o organizationsOUJSON) toOrganizationalUnit() OrganizationalUnit {
	return OrganizationalUnit(o)
}

type listAccountsResponse struct {
	NextToken string                     `json:"NextToken"`
	Accounts  []organizationsAccountJSON `json:"Accounts"`
}

type listOUsResponse struct {
	NextToken           string                `json:"NextToken"`
	OrganizationalUnits []organizationsOUJSON `json:"OrganizationalUnits"`
}

type listRootsResponse struct {
	NextToken string                `json:"NextToken"`
	Roots     []organizationsOUJSON `json:"Roots"`
}

// ListAccounts returns one page of all member accounts in the organization.
// Pass an empty token for the first page; the returned token is empty when done.
func (c *Client) ListAccounts(ctx context.Context, nextToken string) ([]Account, string, error) {
	return c.listAccounts(ctx, organizationsListAccountsTarget, requestBodyWithToken(nil, nextToken))
}

// ListAccountsForParent returns one page of member accounts that are direct
// children of the given parent (a root or organizational unit).
func (c *Client) ListAccountsForParent(
	ctx context.Context,
	parentID, nextToken string,
) ([]Account, string, error) {
	body := requestBodyWithToken(map[string]any{"ParentId": parentID}, nextToken)
	return c.listAccounts(ctx, organizationsListAccountsForParentTarget, body)
}

func (c *Client) listAccounts(ctx context.Context, target string, body []byte) ([]Account, string, error) {
	data, err := c.organizationsPost(ctx, target, body)
	if err != nil {
		return nil, "", fmt.Errorf("list accounts: %w", err)
	}

	var resp listAccountsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse list accounts response: %w", err)
	}

	accounts := make([]Account, len(resp.Accounts))
	for i, a := range resp.Accounts {
		accounts[i] = a.toAccount()
	}
	return accounts, resp.NextToken, nil
}

// ListRoots returns one page of organization roots (the tops of the OU tree).
func (c *Client) ListRoots(ctx context.Context, nextToken string) ([]OrganizationalUnit, string, error) {
	data, err := c.organizationsPost(ctx, organizationsListRootsTarget, requestBodyWithToken(nil, nextToken))
	if err != nil {
		return nil, "", fmt.Errorf("list roots: %w", err)
	}

	var resp listRootsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse list roots response: %w", err)
	}

	roots := make([]OrganizationalUnit, len(resp.Roots))
	for i, r := range resp.Roots {
		roots[i] = r.toOrganizationalUnit()
	}
	return roots, resp.NextToken, nil
}

// ListOrganizationalUnitsForParent returns one page of OUs that are direct
// children of the given parent (a root or organizational unit).
func (c *Client) ListOrganizationalUnitsForParent(
	ctx context.Context,
	parentID, nextToken string,
) ([]OrganizationalUnit, string, error) {
	body := requestBodyWithToken(map[string]any{"ParentId": parentID}, nextToken)
	data, err := c.organizationsPost(ctx, organizationsListOrganizationalUnitsForParent, body)
	if err != nil {
		return nil, "", fmt.Errorf("list organizational units for parent %q: %w", parentID, err)
	}

	var resp listOUsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse list organizational units response: %w", err)
	}

	ous := make([]OrganizationalUnit, len(resp.OrganizationalUnits))
	for i, o := range resp.OrganizationalUnits {
		ous[i] = o.toOrganizationalUnit()
	}
	return ous, resp.NextToken, nil
}

// requestBodyWithToken builds an Organizations JSON request body, adding NextToken
// when paginating. A nil base yields an object carrying only the token (or "{}").
func requestBodyWithToken(base map[string]any, nextToken string) []byte {
	if base == nil {
		base = map[string]any{}
	}
	if nextToken != "" {
		base["NextToken"] = nextToken
	}
	body, _ := json.Marshal(base)
	return body
}
