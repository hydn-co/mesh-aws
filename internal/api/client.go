package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	iamEndpoint = "https://iam.amazonaws.com/"
	iamService  = "iam"
	iamRegion   = "us-east-1"
	iamVersion  = "2010-05-08"

	cloudtrailEndpoint    = "https://cloudtrail.%s.amazonaws.com/"
	cloudtrailService     = "cloudtrail"
	identityStoreEndpoint = "https://identitystore.%s.amazonaws.com/"
	identityStoreService  = "identitystore"
	organizationsEndpoint = "https://organizations.%s.amazonaws.com/"
	organizationsService  = "organizations"

	awsDateTimeFormat = "20060102T150405Z"
	awsDateFormat     = "20060102"
)

// Client sends signed HTTP requests to AWS IAM and CloudTrail.
type Client struct {
	creds        *AWSCredentials
	region       string
	sessionToken string
	http         *http.Client
}

// AWSCredentials holds the AWS signing credentials parsed from connector configuration.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// NewClient creates a new Client from the given credentials.
func NewClient(creds *AWSCredentials, region, sessionToken string) (*Client, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials are required")
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return nil, fmt.Errorf("region is required")
	}
	return &Client{
		creds:        creds,
		region:       region,
		sessionToken: strings.TrimSpace(sessionToken),
		http:         &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// iamPost sends a signed POST to the IAM Query API with the given form parameters.
// The caller must set params["Action"] before calling.
func (c *Client) iamPost(ctx context.Context, params map[string]string) ([]byte, error) {
	params["Version"] = iamVersion

	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	body := v.Encode()
	bodyBytes := []byte(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, iamEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create IAM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c.sign(req, iamService, iamRegion, bodyBytes)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute IAM request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IAM response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseIAMError(data, resp.StatusCode)
	}
	return data, nil
}

// cloudtrailPost sends a signed POST to the CloudTrail JSON API.
func (c *Client) cloudtrailPost(ctx context.Context, target string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf(cloudtrailEndpoint, c.region)
	return c.awsJSONPost(ctx, endpoint, target, cloudtrailService, body)
}

func (c *Client) identityStorePost(ctx context.Context, target string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf(identityStoreEndpoint, c.region)
	return c.awsJSONPost(ctx, endpoint, target, identityStoreService, body)
}

func (c *Client) organizationsPost(ctx context.Context, target string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf(organizationsEndpoint, c.region)
	return c.awsJSONPost(ctx, endpoint, target, organizationsService, body)
}

func (c *Client) awsJSONPost(ctx context.Context, endpoint, target, service string, body []byte) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", service, err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)

	c.sign(req, service, c.region, body)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute %s request: %w", service, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s response body: %w", service, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s HTTP %d: %s", service, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// sign adds AWS Signature Version 4 headers (X-Amz-Date, Authorization, and optionally
// X-Amz-Security-Token) to req. It must be called after all other headers are set.
func (c *Client) sign(req *http.Request, service, region string, body []byte) {
	now := time.Now().UTC()
	dateTime := now.Format(awsDateTimeFormat)
	date := now.Format(awsDateFormat)

	req.Header.Set("X-Amz-Date", dateTime)
	if c.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.sessionToken)
	}

	bodyHash := hexSHA256(body)
	canonHeaders, signedHeaders := buildCanonicalHeaders(req)

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}

	canonReq := strings.Join([]string{
		req.Method,
		canonURI,
		req.URL.RawQuery,
		canonHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	credScope := strings.Join([]string{date, region, service, "aws4_request"}, "/")

	sts := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTime,
		credScope,
		hexSHA256([]byte(canonReq)),
	}, "\n")

	sigKey := deriveSigningKey(c.creds.SecretAccessKey, date, region, service)
	sig := hex.EncodeToString(hmacSHA256(sigKey, []byte(sts)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.creds.AccessKeyID, credScope, signedHeaders, sig,
	))
}

// buildCanonicalHeaders returns the canonical headers string and the signed-headers string
// required by SigV4, built from req's current headers plus the implicit Host header.
func buildCanonicalHeaders(req *http.Request) (canonical, signed string) {
	headers := make(map[string]string)
	headers["host"] = req.URL.Host

	for k, vs := range req.Header {
		headers[strings.ToLower(k)] = strings.TrimSpace(strings.Join(vs, ","))
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(headers[k])
		sb.WriteByte('\n')
	}
	return sb.String(), strings.Join(keys, ";")
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
