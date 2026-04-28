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
	"sort"
	"strings"
	"time"

	"github.com/hydn-co/mesh-aws/internal/credentials"
)

const (
	iamEndpoint = "https://iam.amazonaws.com/"
	iamService  = "iam"
	iamRegion   = "us-east-1"
	iamVersion  = "2010-05-08"

	cloudtrailService = "cloudtrail"

	awsDateTimeFormat = "20060102T150405Z"
	awsDateFormat     = "20060102"
)

// Client sends signed HTTP requests to AWS IAM and CloudTrail.
type Client struct {
	creds *credentials.AWSCredentials
	http  *http.Client
}

// New creates a new Client from the given credentials.
func New(creds *credentials.AWSCredentials) (*Client, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials are required")
	}
	return &Client{
		creds: creds,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// iamPost sends a signed POST to the IAM Query API with the given form parameters.
// The caller must set params["Action"] before calling.
func (c *Client) iamPost(ctx context.Context, params map[string]string) ([]byte, error) {
	params["Version"] = iamVersion

	body := encodeForm(params)
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
	defer resp.Body.Close()

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
	endpoint := "https://cloudtrail." + c.creds.Region + ".amazonaws.com/"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create CloudTrail request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)

	c.sign(req, cloudtrailService, c.creds.Region, body)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute CloudTrail request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CloudTrail response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudtrail HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
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
	if c.creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.creds.SessionToken)
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
	headers := map[string]string{
		"host": req.URL.Host,
	}
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

// encodeForm URL-encodes a map of string parameters into a sorted query string.
// Sorting ensures a stable body, which is needed for correct body hashing in SigV4.
func encodeForm(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(urlEncode(k))
		sb.WriteByte('=')
		sb.WriteString(urlEncode(params[k]))
	}
	return sb.String()
}

// urlEncode percent-encodes a string per RFC 3986, as required by the IAM Query API
// and AWS SigV4 canonical query-string encoding.
func urlEncode(s string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var sb strings.Builder
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(safe, c) >= 0 {
			sb.WriteByte(c)
		} else {
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return sb.String()
}
