package api

import (
	"context"
	"encoding/xml"
	"fmt"
	"time"
)

// ---- IAM entity types -------------------------------------------------------

// IAMUser represents a single IAM user returned by the ListUsers API.
type IAMUser struct {
	UserID     string
	UserName   string
	Path       string
	Arn        string
	CreateDate time.Time
}

// IAMGroup represents a single IAM group.
type IAMGroup struct {
	GroupID    string
	GroupName  string
	Path       string
	Arn        string
	CreateDate time.Time
}

// IAMRole represents a single IAM role.
type IAMRole struct {
	RoleID      string
	RoleName    string
	Description string
}

// IAMPolicy represents a single IAM managed policy.
type IAMPolicy struct {
	PolicyName  string
	PolicyID    string
	Description string
}

// IAMAccessKey represents metadata for one IAM access key.
type IAMAccessKey struct {
	AccessKeyID string
	Status      string
}

// IAMMFADevice represents an MFA device associated with a user.
type IAMMFADevice struct {
	SerialNumber string
}

// ---- IAM XML response structs (unexported) ----------------------------------

type iamUserXML struct {
	UserID     string `xml:"UserId"`
	UserName   string `xml:"UserName"`
	Path       string `xml:"Path"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

func (u iamUserXML) toIAMUser() IAMUser {
	t, _ := time.Parse(time.RFC3339, u.CreateDate)
	return IAMUser{
		UserID:     u.UserID,
		UserName:   u.UserName,
		Path:       u.Path,
		Arn:        u.Arn,
		CreateDate: t,
	}
}

type iamGroupXML struct {
	GroupID    string `xml:"GroupId"`
	GroupName  string `xml:"GroupName"`
	Path       string `xml:"Path"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

func (g iamGroupXML) toIAMGroup() IAMGroup {
	t, _ := time.Parse(time.RFC3339, g.CreateDate)
	return IAMGroup{
		GroupID:    g.GroupID,
		GroupName:  g.GroupName,
		Path:       g.Path,
		Arn:        g.Arn,
		CreateDate: t,
	}
}

// listUsersResp maps the XML response from ListUsers.
type listUsersResp struct {
	Result struct {
		IsTruncated bool `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Users       struct {
			Members []iamUserXML `xml:"member"`
		} `xml:"Users"`
	} `xml:"ListUsersResult"`
}

// listGroupsResp maps the XML response from ListGroups and ListGroupsForUser.
type listGroupsResp struct {
	Result struct {
		IsTruncated bool `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Groups      struct {
			Members []iamGroupXML `xml:"member"`
		} `xml:"Groups"`
	} `xml:"ListGroupsResult"`
}

// listGroupsForUserResp has a different wrapper element name.
type listGroupsForUserResp struct {
	Result struct {
		IsTruncated bool `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Groups      struct {
			Members []iamGroupXML `xml:"member"`
		} `xml:"Groups"`
	} `xml:"ListGroupsForUserResult"`
}

type listRolesResp struct {
	Result struct {
		IsTruncated bool `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Roles       struct {
			Members []struct {
				RoleID      string `xml:"RoleId"`
				RoleName    string `xml:"RoleName"`
				Description string `xml:"Description"`
			} `xml:"member"`
		} `xml:"Roles"`
	} `xml:"ListRolesResult"`
}

type listPoliciesResp struct {
	Result struct {
		IsTruncated bool `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Policies    struct {
			Members []struct {
				PolicyName  string `xml:"PolicyName"`
				PolicyID    string `xml:"PolicyId"`
				Description string `xml:"Description"`
			} `xml:"member"`
		} `xml:"Policies"`
	} `xml:"ListPoliciesResult"`
}

type listAccessKeysResp struct {
	Result struct {
		AccessKeyMetadata struct {
			Members []struct {
				AccessKeyID string `xml:"AccessKeyId"`
				Status      string `xml:"Status"`
			} `xml:"member"`
		} `xml:"AccessKeyMetadata"`
	} `xml:"ListAccessKeysResult"`
}

type listMFADevicesResp struct {
	Result struct {
		MFADevices struct {
			Members []struct {
				SerialNumber string `xml:"SerialNumber"`
			} `xml:"member"`
		} `xml:"MFADevices"`
	} `xml:"ListMFADevicesResult"`
}

// iamErrorResp maps the XML error body returned when IAM returns a non-200 status.
type iamErrorResp struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// IAMError wraps an error response from the IAM API.
type IAMError struct {
	Code    string
	Message string
	Status  int
}

func (e *IAMError) Error() string {
	return fmt.Sprintf("iam %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
}

// IsNoSuchEntity returns true when the IAM API returned a NoSuchEntity code,
// which means the target resource (e.g. login profile) does not exist.
func (e *IAMError) IsNoSuchEntity() bool {
	return e.Code == "NoSuchEntity"
}

func parseIAMError(body []byte, status int) error {
	var errResp iamErrorResp
	if err := xml.Unmarshal(body, &errResp); err == nil && errResp.Error.Code != "" {
		return &IAMError{
			Code:    errResp.Error.Code,
			Message: errResp.Error.Message,
			Status:  status,
		}
	}
	return fmt.Errorf("iam HTTP %d: %s", status, string(body))
}

// ---- IAM API methods --------------------------------------------------------

// ListUsers returns one page of IAM users. Pass an empty marker for the first page.
func (c *Client) ListUsers(ctx context.Context, pathPrefix, marker string) ([]IAMUser, bool, string, error) {
	params := map[string]string{"Action": "ListUsers"}
	if pathPrefix != "" {
		params["PathPrefix"] = pathPrefix
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list users: %w", err)
	}

	var resp listUsersResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list users response: %w", err)
	}

	users := make([]IAMUser, len(resp.Result.Users.Members))
	for i, m := range resp.Result.Users.Members {
		users[i] = m.toIAMUser()
	}
	return users, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListGroups returns one page of IAM groups. Pass an empty marker for the first page.
func (c *Client) ListGroups(ctx context.Context, pathPrefix, marker string) ([]IAMGroup, bool, string, error) {
	params := map[string]string{"Action": "ListGroups"}
	if pathPrefix != "" {
		params["PathPrefix"] = pathPrefix
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list groups: %w", err)
	}

	var resp listGroupsResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list groups response: %w", err)
	}

	groups := make([]IAMGroup, len(resp.Result.Groups.Members))
	for i, m := range resp.Result.Groups.Members {
		groups[i] = m.toIAMGroup()
	}
	return groups, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListGroupsForUser returns one page of IAM groups that the given user belongs to.
func (c *Client) ListGroupsForUser(ctx context.Context, userName, marker string) ([]IAMGroup, bool, string, error) {
	params := map[string]string{
		"Action":   "ListGroupsForUser",
		"UserName": userName,
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list groups for user %q: %w", userName, err)
	}

	var resp listGroupsForUserResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list groups for user response: %w", err)
	}

	groups := make([]IAMGroup, len(resp.Result.Groups.Members))
	for i, m := range resp.Result.Groups.Members {
		groups[i] = m.toIAMGroup()
	}
	return groups, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListRoles returns one page of IAM roles. Pass an empty marker for the first page.
func (c *Client) ListRoles(ctx context.Context, pathPrefix, marker string) ([]IAMRole, bool, string, error) {
	params := map[string]string{"Action": "ListRoles"}
	if pathPrefix != "" {
		params["PathPrefix"] = pathPrefix
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list roles: %w", err)
	}

	var resp listRolesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list roles response: %w", err)
	}

	roles := make([]IAMRole, len(resp.Result.Roles.Members))
	for i, m := range resp.Result.Roles.Members {
		roles[i] = IAMRole{
			RoleID:      m.RoleID,
			RoleName:    m.RoleName,
			Description: m.Description,
		}
	}
	return roles, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListPolicies returns one page of IAM policies filtered by scope (e.g. "Local").
func (c *Client) ListPolicies(ctx context.Context, scope, marker string) ([]IAMPolicy, bool, string, error) {
	params := map[string]string{"Action": "ListPolicies"}
	if scope != "" {
		params["Scope"] = scope
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list policies: %w", err)
	}

	var resp listPoliciesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list policies response: %w", err)
	}

	policies := make([]IAMPolicy, len(resp.Result.Policies.Members))
	for i, m := range resp.Result.Policies.Members {
		policies[i] = IAMPolicy{
			PolicyName:  m.PolicyName,
			PolicyID:    m.PolicyID,
			Description: m.Description,
		}
	}
	return policies, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListAccessKeys returns all access keys for the given IAM user.
func (c *Client) ListAccessKeys(ctx context.Context, userName string) ([]IAMAccessKey, error) {
	data, err := c.iamPost(ctx, map[string]string{
		"Action":   "ListAccessKeys",
		"UserName": userName,
	})
	if err != nil {
		return nil, fmt.Errorf("list access keys for %q: %w", userName, err)
	}

	var resp listAccessKeysResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse list access keys response: %w", err)
	}

	keys := make([]IAMAccessKey, len(resp.Result.AccessKeyMetadata.Members))
	for i, m := range resp.Result.AccessKeyMetadata.Members {
		keys[i] = IAMAccessKey{AccessKeyID: m.AccessKeyID, Status: m.Status}
	}
	return keys, nil
}

// UpdateAccessKey sets the status of an access key to "Active" or "Inactive".
func (c *Client) UpdateAccessKey(ctx context.Context, userName, keyID, status string) error {
	_, err := c.iamPost(ctx, map[string]string{
		"Action":      "UpdateAccessKey",
		"UserName":    userName,
		"AccessKeyId": keyID,
		"Status":      status,
	})
	if err != nil {
		return fmt.Errorf("update access key %q for %q: %w", keyID, userName, err)
	}
	return nil
}

// DeleteLoginProfile removes the console-login password for the given IAM user.
// Returns nil if the user has no login profile (NoSuchEntity is silently ignored).
func (c *Client) DeleteLoginProfile(ctx context.Context, userName string) error {
	_, err := c.iamPost(ctx, map[string]string{
		"Action":   "DeleteLoginProfile",
		"UserName": userName,
	})
	if err != nil {
		var iamErr *IAMError
		if asIAMError(err, &iamErr) && iamErr.IsNoSuchEntity() {
			return nil
		}
		return fmt.Errorf("delete login profile for %q: %w", userName, err)
	}
	return nil
}

// ListMFADevices returns all MFA devices assigned to the given IAM user.
func (c *Client) ListMFADevices(ctx context.Context, userName string) ([]IAMMFADevice, error) {
	data, err := c.iamPost(ctx, map[string]string{
		"Action":   "ListMFADevices",
		"UserName": userName,
	})
	if err != nil {
		return nil, fmt.Errorf("list MFA devices for %q: %w", userName, err)
	}

	var resp listMFADevicesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse list MFA devices response: %w", err)
	}

	devices := make([]IAMMFADevice, len(resp.Result.MFADevices.Members))
	for i, m := range resp.Result.MFADevices.Members {
		devices[i] = IAMMFADevice{SerialNumber: m.SerialNumber}
	}
	return devices, nil
}

// DeactivateMFADevice deactivates the given MFA device for the IAM user.
func (c *Client) DeactivateMFADevice(ctx context.Context, userName, serialNumber string) error {
	_, err := c.iamPost(ctx, map[string]string{
		"Action":       "DeactivateMFADevice",
		"UserName":     userName,
		"SerialNumber": serialNumber,
	})
	if err != nil {
		return fmt.Errorf("deactivate MFA device %q for %q: %w", serialNumber, userName, err)
	}
	return nil
}

// AddUserToGroup adds the given IAM user to the given IAM group.
func (c *Client) AddUserToGroup(ctx context.Context, userName, groupName string) error {
	_, err := c.iamPost(ctx, map[string]string{
		"Action":    "AddUserToGroup",
		"UserName":  userName,
		"GroupName": groupName,
	})
	if err != nil {
		return fmt.Errorf("add user %q to group %q: %w", userName, groupName, err)
	}
	return nil
}

// RemoveUserFromGroup removes the given IAM user from the given IAM group.
func (c *Client) RemoveUserFromGroup(ctx context.Context, userName, groupName string) error {
	_, err := c.iamPost(ctx, map[string]string{
		"Action":    "RemoveUserFromGroup",
		"UserName":  userName,
		"GroupName": groupName,
	})
	if err != nil {
		return fmt.Errorf("remove user %q from group %q: %w", userName, groupName, err)
	}
	return nil
}

// asIAMError checks whether err (or its cause) is an *IAMError and writes it to target.
func asIAMError(err error, target **IAMError) bool {
	if e, ok := err.(*IAMError); ok {
		*target = e
		return true
	}
	return false
}
