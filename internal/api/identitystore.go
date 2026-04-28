package api

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	identityStoreListUsersTarget  = "AWSIdentityStore.ListUsers"
	identityStoreListGroupsTarget = "AWSIdentityStore.ListGroups"
)

// IdentityStoreUser represents a user returned by the AWS Identity Store API.
type IdentityStoreUser struct {
	UserID       string
	UserName     string
	DisplayName  string
	GivenName    string
	FamilyName   string
	MiddleName   string
	Active       bool
	Emails       []IdentityStoreEmail
	PhoneNumbers []IdentityStorePhoneNumber
}

// IdentityStoreEmail represents an email address returned by the Identity Store API.
type IdentityStoreEmail struct {
	Value   string
	Primary bool
}

// IdentityStorePhoneNumber represents a phone number returned by the Identity Store API.
type IdentityStorePhoneNumber struct {
	Value   string
	Primary bool
}

// IdentityStoreGroup represents a group returned by the AWS Identity Store API.
type IdentityStoreGroup struct {
	GroupID     string
	DisplayName string
	Description string
}

type identityStoreListUsersRequest struct {
	IdentityStoreID string `json:"IdentityStoreId"`
	MaxResults      int    `json:"MaxResults,omitempty"`
	NextToken       string `json:"NextToken,omitempty"`
}

type identityStoreListUsersResponse struct {
	Users     []identityStoreUserJSON `json:"Users"`
	NextToken string                  `json:"NextToken"`
}

type identityStoreUserJSON struct {
	UserID       string                   `json:"UserId"`
	UserName     string                   `json:"UserName"`
	DisplayName  string                   `json:"DisplayName"`
	Active       bool                     `json:"Active"`
	Name         *identityStoreNameJSON   `json:"Name"`
	Emails       []identityStoreEmailJSON `json:"Emails"`
	PhoneNumbers []identityStorePhoneJSON `json:"PhoneNumbers"`
}

type identityStoreNameJSON struct {
	GivenName  string `json:"GivenName"`
	FamilyName string `json:"FamilyName"`
	MiddleName string `json:"MiddleName"`
}

type identityStoreEmailJSON struct {
	Value   string `json:"Value"`
	Primary bool   `json:"Primary"`
}

type identityStorePhoneJSON struct {
	Value   string `json:"Value"`
	Primary bool   `json:"Primary"`
}

type identityStoreListGroupsRequest struct {
	IdentityStoreID string `json:"IdentityStoreId"`
	MaxResults      int    `json:"MaxResults,omitempty"`
	NextToken       string `json:"NextToken,omitempty"`
}

type identityStoreListGroupsResponse struct {
	Groups    []identityStoreGroupJSON `json:"Groups"`
	NextToken string                   `json:"NextToken"`
}

type identityStoreGroupJSON struct {
	GroupID     string `json:"GroupId"`
	DisplayName string `json:"DisplayName"`
	Description string `json:"Description"`
}

// ListIdentityStoreUsers returns one page of users for the given Identity Store ID.
func (c *Client) ListIdentityStoreUsers(
	ctx context.Context,
	identityStoreID, nextToken string,
) ([]IdentityStoreUser, string, error) {
	requestBody, err := json.Marshal(identityStoreListUsersRequest{
		IdentityStoreID: identityStoreID,
		MaxResults:      100,
		NextToken:       nextToken,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal Identity Store list users request: %w", err)
	}

	responseBody, err := c.identityStorePost(ctx, identityStoreListUsersTarget, requestBody)
	if err != nil {
		return nil, "", fmt.Errorf("list Identity Store users: %w", err)
	}

	var response identityStoreListUsersResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, "", fmt.Errorf("parse Identity Store list users response: %w", err)
	}

	users := make([]IdentityStoreUser, 0, len(response.Users))
	for _, user := range response.Users {
		mapped := IdentityStoreUser{
			UserID:      user.UserID,
			UserName:    user.UserName,
			DisplayName: user.DisplayName,
			Active:      user.Active,
		}
		if user.Name != nil {
			mapped.GivenName = user.Name.GivenName
			mapped.FamilyName = user.Name.FamilyName
			mapped.MiddleName = user.Name.MiddleName
		}
		for _, email := range user.Emails {
			mapped.Emails = append(mapped.Emails, IdentityStoreEmail(email))
		}
		for _, phone := range user.PhoneNumbers {
			mapped.PhoneNumbers = append(mapped.PhoneNumbers, IdentityStorePhoneNumber(phone))
		}
		users = append(users, mapped)
	}

	return users, response.NextToken, nil
}

// ListIdentityStoreGroups returns one page of groups for the given Identity Store ID.
func (c *Client) ListIdentityStoreGroups(
	ctx context.Context,
	identityStoreID, nextToken string,
) ([]IdentityStoreGroup, string, error) {
	requestBody, err := json.Marshal(identityStoreListGroupsRequest{
		IdentityStoreID: identityStoreID,
		MaxResults:      100,
		NextToken:       nextToken,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal Identity Store list groups request: %w", err)
	}

	responseBody, err := c.identityStorePost(ctx, identityStoreListGroupsTarget, requestBody)
	if err != nil {
		return nil, "", fmt.Errorf("list Identity Store groups: %w", err)
	}

	var response identityStoreListGroupsResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, "", fmt.Errorf("parse Identity Store list groups response: %w", err)
	}

	groups := make([]IdentityStoreGroup, 0, len(response.Groups))
	for _, group := range response.Groups {
		groups = append(groups, IdentityStoreGroup(group))
	}

	return groups, response.NextToken, nil
}
