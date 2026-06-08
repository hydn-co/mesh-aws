package api

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	stsEndpoint = "https://sts.%s.amazonaws.com/"
	stsService  = "sts"
	stsVersion  = "2011-06-15"
)

// AssumedCredentials holds the temporary credentials returned by STS AssumeRole.
// They plug directly into NewClient (AccessKeyID + SecretAccessKey as
// AWSCredentials, SessionToken as the session token) to sign requests against a
// member account.
type AssumedCredentials struct {
	Expiration      time.Time
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type assumeRoleResp struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
}

// stsPost sends a signed POST to the regional STS Query API. STS is region-scoped,
// so the request is signed for the client's configured region.
func (c *Client) stsPost(ctx context.Context, params map[string]string) ([]byte, error) {
	params["Version"] = stsVersion

	endpoint := fmt.Sprintf(stsEndpoint, c.region)
	data, status, err := c.formPost(ctx, endpoint, stsService, c.region, params)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, parseSTSError(data, status)
	}
	return data, nil
}

// AssumeRole assumes the given role ARN and returns temporary credentials. The
// optional externalID is sent when the member-account role's trust policy
// requires an sts:ExternalId condition.
func (c *Client) AssumeRole(
	ctx context.Context,
	roleArn, sessionName, externalID string,
) (*AssumedCredentials, error) {
	params := map[string]string{
		"Action":          "AssumeRole",
		"RoleArn":         roleArn,
		"RoleSessionName": sessionName,
	}
	if externalID != "" {
		params["ExternalId"] = externalID
	}

	data, err := c.stsPost(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("assume role %q: %w", roleArn, err)
	}

	var resp assumeRoleResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse assume role response: %w", err)
	}

	creds := resp.Result.Credentials
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("assume role %q: response contained no credentials", roleArn)
	}

	assumed := &AssumedCredentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}
	if creds.Expiration != "" {
		assumed.Expiration, _ = time.Parse(time.RFC3339, creds.Expiration)
	}
	return assumed, nil
}

// parseSTSError maps a non-200 STS Query API response to an error. STS shares the
// AWS Query XML error envelope (<ErrorResponse><Error><Code>/<Message>).
func parseSTSError(body []byte, status int) error {
	var errResp iamErrorResp
	if err := xml.Unmarshal(body, &errResp); err == nil && errResp.Error.Code != "" {
		return fmt.Errorf("sts %s: %s (HTTP %d)", errResp.Error.Code, errResp.Error.Message, status)
	}
	return fmt.Errorf("sts HTTP %d: %s", status, strings.TrimSpace(string(body)))
}
