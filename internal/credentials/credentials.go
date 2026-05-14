package credentials

import (
	"encoding/json"
	"fmt"
)

// AWSCredentials holds the AWS authentication fields parsed from connector configuration.
type AWSCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// Parse decodes AWSCredentials from a raw JSON message.
func Parse(raw json.RawMessage) (*AWSCredentials, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("credentials are required")
	}
	var creds AWSCredentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return nil, fmt.Errorf("parse AWS credentials: %w", err)
	}
	if creds.AccessKeyID == "" {
		return nil, fmt.Errorf("access_key_id is required")
	}
	if creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("secret_access_key is required")
	}
	return &creds, nil
}
