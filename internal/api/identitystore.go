package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	identityStoreListUsersTarget            = "AWSIdentityStore.ListUsers"
	identityStoreListGroupsTarget           = "AWSIdentityStore.ListGroups"
	identityStoreListGroupMembershipsTarget = "AWSIdentityStore.ListGroupMemberships"
)

// IdentityStoreUser represents a user returned by the AWS Identity Store API.
type IdentityStoreUser struct {
	CreatedAt    time.Time
	UserID       string
	UserName     string
	DisplayName  string
	GivenName    string
	FamilyName   string
	MiddleName   string
	Emails       []IdentityStoreEmail
	PhoneNumbers []IdentityStorePhoneNumber
	Active       bool
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
	CreatedAt   time.Time
	GroupID     string
	DisplayName string
	Description string
}

// IdentityStoreGroupMembership represents a group membership returned by the AWS Identity Store API.
type IdentityStoreGroupMembership struct {
	CreatedAt    time.Time
	MembershipID string
	GroupID      string
	MemberUserID string
}

type identityStoreListUsersRequest struct {
	IdentityStoreID string `json:"IdentityStoreId"`
	NextToken       string `json:"NextToken,omitempty"`
	MaxResults      int    `json:"MaxResults,omitempty"`
}

type identityStoreListUsersResponse struct {
	NextToken string                  `json:"NextToken"`
	Users     []identityStoreUserJSON `json:"Users"`
}

type identityStoreUserJSON struct {
	Name         *identityStoreNameJSON   `json:"Name"`
	UserID       string                   `json:"UserId"`
	UserName     string                   `json:"UserName"`
	DisplayName  string                   `json:"DisplayName"`
	Emails       []identityStoreEmailJSON `json:"Emails"`
	PhoneNumbers []identityStorePhoneJSON `json:"PhoneNumbers"`
	CreatedAt    float64                  `json:"CreatedAt"`
	Active       bool                     `json:"Active"`
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
	NextToken       string `json:"NextToken,omitempty"`
	MaxResults      int    `json:"MaxResults,omitempty"`
}

type identityStoreListGroupsResponse struct {
	NextToken string                   `json:"NextToken"`
	Groups    []identityStoreGroupJSON `json:"Groups"`
}

type identityStoreGroupJSON struct {
	GroupID     string  `json:"GroupId"`
	DisplayName string  `json:"DisplayName"`
	Description string  `json:"Description"`
	CreatedAt   float64 `json:"CreatedAt"`
}

type identityStoreListGroupMembershipsRequest struct {
	IdentityStoreID string `json:"IdentityStoreId"`
	GroupID         string `json:"GroupId"`
	NextToken       string `json:"NextToken,omitempty"`
	MaxResults      int    `json:"MaxResults,omitempty"`
}

type identityStoreListGroupMembershipsResponse struct {
	NextToken        string                             `json:"NextToken"`
	GroupMemberships []identityStoreGroupMembershipJSON `json:"GroupMemberships"`
}

type identityStoreGroupMembershipJSON struct {
	MembershipID string `json:"MembershipId"`
	GroupID      string `json:"GroupId"`
	MemberID     struct {
		UserID string `json:"UserId"`
	} `json:"MemberId"`
	CreatedAt float64 `json:"CreatedAt"`
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
		if user.CreatedAt > 0 {
			mapped.CreatedAt = time.Unix(int64(user.CreatedAt), 0).UTC()
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
		mapped := IdentityStoreGroup{
			GroupID:     group.GroupID,
			DisplayName: group.DisplayName,
			Description: group.Description,
		}
		if group.CreatedAt > 0 {
			mapped.CreatedAt = time.Unix(int64(group.CreatedAt), 0).UTC()
		}
		groups = append(groups, mapped)
	}

	return groups, response.NextToken, nil
}

// ListGroupMemberships returns one page of group memberships for the given Identity Store group.
func (c *Client) ListGroupMemberships(
	ctx context.Context,
	identityStoreID, groupID, nextToken string,
) ([]IdentityStoreGroupMembership, string, error) {
	requestBody, err := json.Marshal(identityStoreListGroupMembershipsRequest{
		IdentityStoreID: identityStoreID,
		GroupID:         groupID,
		MaxResults:      100,
		NextToken:       nextToken,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal Identity Store list group memberships request: %w", err)
	}

	responseBody, err := c.identityStorePost(ctx, identityStoreListGroupMembershipsTarget, requestBody)
	if err != nil {
		return nil, "", fmt.Errorf("list Identity Store group memberships: %w", err)
	}

	var response identityStoreListGroupMembershipsResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, "", fmt.Errorf("parse Identity Store list group memberships response: %w", err)
	}

	memberships := make([]IdentityStoreGroupMembership, 0, len(response.GroupMemberships))
	for _, membership := range response.GroupMemberships {
		mapped := IdentityStoreGroupMembership{
			MembershipID: membership.MembershipID,
			GroupID:      membership.GroupID,
			MemberUserID: membership.MemberID.UserID,
		}
		if membership.CreatedAt > 0 {
			mapped.CreatedAt = time.Unix(int64(membership.CreatedAt), 0).UTC()
		}
		memberships = append(memberships, mapped)
	}

	return memberships, response.NextToken, nil
}
