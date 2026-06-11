package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ---- IAM entity types -------------------------------------------------------

// IAMUser represents a single IAM user returned by the ListUsers API.
type IAMUser struct {
	CreateDate time.Time
	UserID     string
	UserName   string
	Path       string
	Arn        string
}

// IAMGroup represents a single IAM group.
type IAMGroup struct {
	CreateDate time.Time
	GroupID    string
	GroupName  string
	Path       string
	Arn        string
}

// IAMRole represents a single IAM role.
type IAMRole struct {
	RoleID            string
	RoleName          string
	Arn               string
	Description       string
	ServicePrincipals []string
	AWSPrincipals     []string
}

// IAMPolicy represents a single IAM managed policy.
type IAMPolicy struct {
	PolicyName  string
	PolicyID    string
	Description string
}

// IAMAttachedPolicy represents a managed policy attached to a role.
type IAMAttachedPolicy struct {
	PolicyName string
	PolicyArn  string
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

// IAMVirtualMFADevice represents an assigned virtual MFA device.
type IAMVirtualMFADevice struct {
	SerialNumber string
	EnableDate   time.Time
	UserID       string
	UserName     string
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
		Marker string `xml:"Marker"`
		Users  struct {
			Members []iamUserXML `xml:"member"`
		} `xml:"Users"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListUsersResult"`
}

// listGroupsResp maps the XML response from ListGroups and ListGroupsForUser.
type listGroupsResp struct {
	Result struct {
		Marker string `xml:"Marker"`
		Groups struct {
			Members []iamGroupXML `xml:"member"`
		} `xml:"Groups"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListGroupsResult"`
}

// listGroupsForUserResp has a different wrapper element name.
type listGroupsForUserResp struct {
	Result struct {
		Marker string `xml:"Marker"`
		Groups struct {
			Members []iamGroupXML `xml:"member"`
		} `xml:"Groups"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListGroupsForUserResult"`
}

type listRolesResp struct {
	Result struct {
		Marker string `xml:"Marker"`
		Roles  struct {
			Members []iamRoleXML `xml:"member"`
		} `xml:"Roles"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListRolesResult"`
}

type iamRoleXML struct {
	RoleID                   string `xml:"RoleId"`
	RoleName                 string `xml:"RoleName"`
	Arn                      string `xml:"Arn"`
	Description              string `xml:"Description"`
	AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
}

func (r iamRoleXML) toIAMRole() IAMRole {
	return IAMRole{
		RoleID:            r.RoleID,
		RoleName:          r.RoleName,
		Arn:               r.Arn,
		Description:       r.Description,
		ServicePrincipals: extractServicePrincipals(r.AssumeRolePolicyDocument),
		AWSPrincipals:     extractAWSPrincipals(r.AssumeRolePolicyDocument),
	}
}

func extractServicePrincipals(encodedPolicy string) []string {
	if encodedPolicy == "" {
		return nil
	}

	decodedPolicy, err := url.QueryUnescape(encodedPolicy)
	if err != nil {
		decodedPolicy = encodedPolicy
	}

	var policyDoc map[string]any
	if err := json.Unmarshal([]byte(decodedPolicy), &policyDoc); err != nil {
		return nil
	}

	statements, ok := toObjectSlice(policyDoc["Statement"])
	if !ok {
		return nil
	}

	seen := map[string]struct{}{}
	principals := make([]string, 0)
	for _, statement := range statements {
		if !statementAllowsServiceAssumeRole(statement) {
			continue
		}

		principalMap, ok := toObject(statement["Principal"])
		if !ok {
			continue
		}

		services, ok := toStringSlice(principalMap["Service"])
		if !ok {
			continue
		}

		for _, service := range services {
			service = strings.TrimSpace(service)
			if service == "" {
				continue
			}
			if _, exists := seen[service]; exists {
				continue
			}
			seen[service] = struct{}{}
			principals = append(principals, service)
		}
	}

	if len(principals) == 0 {
		return nil
	}

	return principals
}

// extractAWSPrincipals returns the concrete AWS principal ARNs (account-root, user, or role
// ARNs) that are allowed to assume the role described by the encoded trust policy. Wildcard
// principals ("*") and any value that is not an IAM ARN are skipped so that emitted
// AccountRole references always point at a concrete principal.
func extractAWSPrincipals(encodedPolicy string) []string {
	if encodedPolicy == "" {
		return nil
	}

	decodedPolicy, err := url.QueryUnescape(encodedPolicy)
	if err != nil {
		decodedPolicy = encodedPolicy
	}

	var policyDoc map[string]any
	if err := json.Unmarshal([]byte(decodedPolicy), &policyDoc); err != nil {
		return nil
	}

	statements, ok := toObjectSlice(policyDoc["Statement"])
	if !ok {
		return nil
	}

	seen := map[string]struct{}{}
	principals := make([]string, 0)
	for _, statement := range statements {
		if !statementAllowsServiceAssumeRole(statement) {
			continue
		}

		principalMap, ok := toObject(statement["Principal"])
		if !ok {
			continue
		}

		arns, ok := toStringSlice(principalMap["AWS"])
		if !ok {
			continue
		}

		for _, arn := range arns {
			arn = strings.TrimSpace(arn)
			if !strings.HasPrefix(arn, "arn:aws:iam::") {
				continue
			}
			if _, exists := seen[arn]; exists {
				continue
			}
			seen[arn] = struct{}{}
			principals = append(principals, arn)
		}
	}

	if len(principals) == 0 {
		return nil
	}

	return principals
}

func statementAllowsServiceAssumeRole(statement map[string]any) bool {
	effect, ok := statement["Effect"].(string)
	if !ok || !strings.EqualFold(strings.TrimSpace(effect), "Allow") {
		return false
	}

	actions, ok := toStringSlice(statement["Action"])
	if !ok {
		return false
	}

	for _, action := range actions {
		if strings.EqualFold(strings.TrimSpace(action), "sts:AssumeRole") {
			return true
		}
	}

	return false
}

// extractAllowedActions returns the deduplicated, sorted IAM actions granted by
// the Allow statements of the encoded policy document. Deny statements and
// NotAction grants are skipped — the catalog has no per-permission deny
// dimension yet (tracked as a follow-up).
func extractAllowedActions(encodedPolicy string) []string {
	if encodedPolicy == "" {
		return nil
	}

	decodedPolicy, err := url.QueryUnescape(encodedPolicy)
	if err != nil {
		decodedPolicy = encodedPolicy
	}

	var policyDoc map[string]any
	if err := json.Unmarshal([]byte(decodedPolicy), &policyDoc); err != nil {
		return nil
	}

	statements, ok := toObjectSlice(policyDoc["Statement"])
	if !ok {
		return nil
	}

	seen := map[string]struct{}{}
	actions := make([]string, 0)
	for _, statement := range statements {
		effect, ok := statement["Effect"].(string)
		if !ok || !strings.EqualFold(strings.TrimSpace(effect), "Allow") {
			continue
		}

		granted, ok := toStringSlice(statement["Action"])
		if !ok {
			continue
		}

		for _, action := range granted {
			action = strings.TrimSpace(action)
			if action == "" {
				continue
			}
			if _, exists := seen[action]; exists {
				continue
			}
			seen[action] = struct{}{}
			actions = append(actions, action)
		}
	}

	if len(actions) == 0 {
		return nil
	}

	sort.Strings(actions)
	return actions
}

func toObject(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func toObjectSlice(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return []map[string]any{typed}, true
	case []any:
		objects := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			objects = append(objects, object)
		}
		if len(objects) == 0 {
			return nil, false
		}
		return objects, true
	default:
		return nil, false
	}
}

func toStringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, true
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				continue
			}
			values = append(values, text)
		}
		if len(values) == 0 {
			return nil, false
		}
		return values, true
	default:
		return nil, false
	}
}

type listPoliciesResp struct {
	Result struct {
		Marker   string `xml:"Marker"`
		Policies struct {
			Members []iamPolicyXML `xml:"member"`
		} `xml:"Policies"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListPoliciesResult"`
}

type iamPolicyXML struct {
	PolicyName  string `xml:"PolicyName"`
	PolicyID    string `xml:"PolicyId"`
	Description string `xml:"Description"`
}

type listAttachedRolePoliciesResp struct {
	Result struct {
		Marker           string `xml:"Marker"`
		AttachedPolicies struct {
			Members []iamAttachedPolicyXML `xml:"member"`
		} `xml:"AttachedPolicies"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListAttachedRolePoliciesResult"`
}

type iamAttachedPolicyXML struct {
	PolicyName string `xml:"PolicyName"`
	PolicyArn  string `xml:"PolicyArn"`
}

type listRolePoliciesResp struct {
	Result struct {
		Marker      string `xml:"Marker"`
		PolicyNames struct {
			Members []string `xml:"member"`
		} `xml:"PolicyNames"`
		IsTruncated bool `xml:"IsTruncated"`
	} `xml:"ListRolePoliciesResult"`
}

type getPolicyResp struct {
	Result struct {
		Policy struct {
			DefaultVersionID string `xml:"DefaultVersionId"`
		} `xml:"Policy"`
	} `xml:"GetPolicyResult"`
}

type getPolicyVersionResp struct {
	Result struct {
		PolicyVersion struct {
			Document string `xml:"Document"`
		} `xml:"PolicyVersion"`
	} `xml:"GetPolicyVersionResult"`
}

type getRolePolicyResp struct {
	Result struct {
		PolicyDocument string `xml:"PolicyDocument"`
	} `xml:"GetRolePolicyResult"`
}

type listAccessKeysResp struct {
	Result struct {
		AccessKeyMetadata iamAccessKeyMetadata `xml:"AccessKeyMetadata"`
	} `xml:"ListAccessKeysResult"`
}

type iamAccessKeyMetadata struct {
	Members []iamAccessKeyXML `xml:"member"`
}

type iamAccessKeyXML struct {
	AccessKeyID string `xml:"AccessKeyId"`
	Status      string `xml:"Status"`
}

type listMFADevicesResp struct {
	Result struct {
		MFADevices iamMFADevices `xml:"MFADevices"`
	} `xml:"ListMFADevicesResult"`
}

type iamMFADevices struct {
	Members []iamMFADeviceXML `xml:"member"`
}

type iamMFADeviceXML struct {
	SerialNumber string `xml:"SerialNumber"`
}

type listVirtualMFADevicesResp struct {
	Result struct {
		Marker            string               `xml:"Marker"`
		VirtualMFADevices iamVirtualMFADevices `xml:"VirtualMFADevices"`
		IsTruncated       bool                 `xml:"IsTruncated"`
	} `xml:"ListVirtualMFADevicesResult"`
}

type iamVirtualMFADevices struct {
	Members []iamVirtualMFADeviceXML `xml:"member"`
}

type iamVirtualMFADeviceXML struct {
	SerialNumber string            `xml:"SerialNumber"`
	EnableDate   string            `xml:"EnableDate"`
	User         iamVirtualMFAUser `xml:"User"`
}

type iamVirtualMFAUser struct {
	UserID   string `xml:"UserId"`
	UserName string `xml:"UserName"`
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
		roles[i] = m.toIAMRole()
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
		policies[i] = IAMPolicy(m)
	}
	return policies, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListAttachedRolePolicies returns one page of managed policies attached to the given role.
// Pass an empty marker for the first page.
func (c *Client) ListAttachedRolePolicies(
	ctx context.Context,
	roleName, marker string,
) ([]IAMAttachedPolicy, bool, string, error) {
	params := map[string]string{
		"Action":   "ListAttachedRolePolicies",
		"RoleName": roleName,
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list attached role policies for %q: %w", roleName, err)
	}

	var resp listAttachedRolePoliciesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list attached role policies response: %w", err)
	}

	policies := make([]IAMAttachedPolicy, len(resp.Result.AttachedPolicies.Members))
	for i, m := range resp.Result.AttachedPolicies.Members {
		policies[i] = IAMAttachedPolicy(m)
	}
	return policies, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// ListRolePolicies returns one page of inline policy names embedded in the given role.
// Pass an empty marker for the first page.
func (c *Client) ListRolePolicies(ctx context.Context, roleName, marker string) ([]string, bool, string, error) {
	params := map[string]string{
		"Action":   "ListRolePolicies",
		"RoleName": roleName,
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list role policies for %q: %w", roleName, err)
	}

	var resp listRolePoliciesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list role policies response: %w", err)
	}

	return resp.Result.PolicyNames.Members, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// GetPolicy returns the default (active) version ID of the given managed policy.
func (c *Client) GetPolicy(ctx context.Context, policyArn string) (string, error) {
	data, err := c.iamPost(ctx, map[string]string{
		"Action":    "GetPolicy",
		"PolicyArn": policyArn,
	})
	if err != nil {
		return "", fmt.Errorf("get policy %q: %w", policyArn, err)
	}

	var resp getPolicyResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse get policy response: %w", err)
	}

	return resp.Result.Policy.DefaultVersionID, nil
}

// GetPolicyVersion returns the IAM actions allowed by the given managed-policy
// version (its URL-encoded document's Allow statements, deduplicated and sorted).
func (c *Client) GetPolicyVersion(ctx context.Context, policyArn, versionID string) ([]string, error) {
	data, err := c.iamPost(ctx, map[string]string{
		"Action":    "GetPolicyVersion",
		"PolicyArn": policyArn,
		"VersionId": versionID,
	})
	if err != nil {
		return nil, fmt.Errorf("get policy version %q of %q: %w", versionID, policyArn, err)
	}

	var resp getPolicyVersionResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse get policy version response: %w", err)
	}

	return extractAllowedActions(resp.Result.PolicyVersion.Document), nil
}

// GetRolePolicy returns the IAM actions allowed by the named inline policy
// embedded in the given role (its URL-encoded document's Allow statements,
// deduplicated and sorted).
func (c *Client) GetRolePolicy(ctx context.Context, roleName, policyName string) ([]string, error) {
	data, err := c.iamPost(ctx, map[string]string{
		"Action":     "GetRolePolicy",
		"RoleName":   roleName,
		"PolicyName": policyName,
	})
	if err != nil {
		return nil, fmt.Errorf("get role policy %q for %q: %w", policyName, roleName, err)
	}

	var resp getRolePolicyResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse get role policy response: %w", err)
	}

	return extractAllowedActions(resp.Result.PolicyDocument), nil
}

// IAMManagedPolicyActions resolves a managed policy ARN to the IAM actions its
// default version allows, retrying each call on throttling.
func (c *Client) IAMManagedPolicyActions(ctx context.Context, policyArn string) ([]string, error) {
	var versionID string
	if err := awsRetryOperation(ctx, func(ctx context.Context) error {
		var err error
		versionID, err = c.GetPolicy(ctx, policyArn)
		return err
	}); err != nil {
		return nil, err
	}

	var actions []string
	if err := awsRetryOperation(ctx, func(ctx context.Context) error {
		var err error
		actions, err = c.GetPolicyVersion(ctx, policyArn, versionID)
		return err
	}); err != nil {
		return nil, err
	}
	return actions, nil
}

// IAMInlineRolePolicyActions resolves a role's named inline policy to the IAM
// actions it allows, retrying on throttling.
func (c *Client) IAMInlineRolePolicyActions(ctx context.Context, roleName, policyName string) ([]string, error) {
	var actions []string
	if err := awsRetryOperation(ctx, func(ctx context.Context) error {
		var err error
		actions, err = c.GetRolePolicy(ctx, roleName, policyName)
		return err
	}); err != nil {
		return nil, err
	}
	return actions, nil
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
		keys[i] = IAMAccessKey(m)
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
		devices[i] = IAMMFADevice(m)
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

// CreateUser creates a new IAM user with the given name and optional path.
func (c *Client) CreateUser(ctx context.Context, userName, path string) error {
	params := map[string]string{
		"Action":   "CreateUser",
		"UserName": userName,
	}
	if path != "" {
		params["Path"] = path
	}
	_, err := c.iamPost(ctx, params)
	if err != nil {
		return fmt.Errorf("create user %q: %w", userName, err)
	}
	return nil
}

// CreateGroup creates a new IAM group with the given name and optional path.
func (c *Client) CreateGroup(ctx context.Context, groupName, path string) error {
	params := map[string]string{
		"Action":    "CreateGroup",
		"GroupName": groupName,
	}
	if path != "" {
		params["Path"] = path
	}
	_, err := c.iamPost(ctx, params)
	if err != nil {
		return fmt.Errorf("create group %q: %w", groupName, err)
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

// ListVirtualMFADevices returns one page of assigned virtual MFA devices.
func (c *Client) ListVirtualMFADevices(
	ctx context.Context,
	marker string,
) ([]IAMVirtualMFADevice, bool, string, error) {
	params := map[string]string{
		"Action":           "ListVirtualMFADevices",
		"AssignmentStatus": "Assigned",
	}
	if marker != "" {
		params["Marker"] = marker
	}

	data, err := c.iamPost(ctx, params)
	if err != nil {
		return nil, false, "", fmt.Errorf("list virtual MFA devices: %w", err)
	}

	var resp listVirtualMFADevicesResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, false, "", fmt.Errorf("parse list virtual MFA devices response: %w", err)
	}

	devices := make([]IAMVirtualMFADevice, len(resp.Result.VirtualMFADevices.Members))
	for index, member := range resp.Result.VirtualMFADevices.Members {
		var enableDate time.Time
		if member.EnableDate != "" {
			enableDate, _ = time.Parse(time.RFC3339, member.EnableDate)
		}
		devices[index] = IAMVirtualMFADevice{
			SerialNumber: member.SerialNumber,
			EnableDate:   enableDate,
			UserID:       member.User.UserID,
			UserName:     member.User.UserName,
		}
	}

	return devices, resp.Result.IsTruncated, resp.Result.Marker, nil
}

// asIAMError checks whether err (or its cause) is an *IAMError and writes it to target.
func asIAMError(err error, target **IAMError) bool {
	if e, ok := err.(*IAMError); ok {
		*target = e
		return true
	}
	return false
}

// IsNoSuchEntity reports whether err, or any error it wraps, is an IAM NoSuchEntity error.
// Collectors use it to skip resources that were deleted mid-enumeration instead of failing.
func IsNoSuchEntity(err error) bool {
	var iamErr *IAMError
	if errors.As(err, &iamErr) {
		return iamErr.IsNoSuchEntity()
	}
	return false
}
