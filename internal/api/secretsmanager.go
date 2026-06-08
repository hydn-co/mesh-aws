package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	secretsManagerEndpoint    = "https://secretsmanager.%s.amazonaws.com/"
	secretsManagerService     = "secretsmanager"
	secretsManagerListSecrets = "secretsmanager.ListSecrets"
)

// Secret holds Secrets Manager metadata for one secret. Secret values are never
// retrieved: collection is metadata-only so auditors can confirm a credential is
// stored (and how it is protected/rotated) without exposing its contents. Note
// that ListSecrets is eventually consistent and may omit changes from the last
// five minutes.
type Secret struct {
	LastChangedDate   time.Time
	LastAccessedDate  time.Time
	Tags              map[string]string
	ARN               string
	Name              string
	Description       string
	KmsKeyID          string
	OwningService     string
	PrimaryRegion     string
	RotationLambdaARN string
	RotationEnabled   bool
}

type secretsManagerSecretJSON struct {
	ARN               string                  `json:"ARN"`
	Name              string                  `json:"Name"`
	Description       string                  `json:"Description"`
	KmsKeyID          string                  `json:"KmsKeyId"`
	OwningService     string                  `json:"OwningService"`
	PrimaryRegion     string                  `json:"PrimaryRegion"`
	RotationLambdaARN string                  `json:"RotationLambdaARN"`
	Tags              []secretsManagerTagJSON `json:"Tags"`
	LastChangedDate   float64                 `json:"LastChangedDate"`
	LastAccessedDate  float64                 `json:"LastAccessedDate"`
	RotationEnabled   bool                    `json:"RotationEnabled"`
}

type secretsManagerTagJSON struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (s secretsManagerSecretJSON) toSecret() Secret {
	secret := Secret{
		ARN:               s.ARN,
		Name:              s.Name,
		Description:       s.Description,
		KmsKeyID:          s.KmsKeyID,
		OwningService:     s.OwningService,
		PrimaryRegion:     s.PrimaryRegion,
		RotationLambdaARN: s.RotationLambdaARN,
		RotationEnabled:   s.RotationEnabled,
		LastChangedDate:   epochSecondsToTime(s.LastChangedDate),
		LastAccessedDate:  epochSecondsToTime(s.LastAccessedDate),
	}
	if len(s.Tags) > 0 {
		secret.Tags = make(map[string]string, len(s.Tags))
		for _, tag := range s.Tags {
			secret.Tags[tag.Key] = tag.Value
		}
	}
	return secret
}

type listSecretsResponse struct {
	NextToken  string                     `json:"NextToken"`
	SecretList []secretsManagerSecretJSON `json:"SecretList"`
}

func (c *Client) secretsManagerPost(ctx context.Context, target string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf(secretsManagerEndpoint, c.region)
	return c.awsJSONPost(ctx, endpoint, target, secretsManagerService, body)
}

// ListSecrets returns one page of Secrets Manager secret metadata in the client's
// region. Pass an empty token for the first page; the returned token is empty when done.
func (c *Client) ListSecrets(ctx context.Context, nextToken string) ([]Secret, string, error) {
	body := requestBodyWithToken(nil, nextToken)
	data, err := c.secretsManagerPost(ctx, secretsManagerListSecrets, body)
	if err != nil {
		return nil, "", fmt.Errorf("list secrets: %w", err)
	}

	var resp listSecretsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse list secrets response: %w", err)
	}

	secrets := make([]Secret, len(resp.SecretList))
	for i, s := range resp.SecretList {
		secrets[i] = s.toSecret()
	}
	return secrets, resp.NextToken, nil
}

// epochSecondsToTime converts an AWS JSON epoch-seconds timestamp to UTC time,
// returning the zero time for absent/zero values.
func epochSecondsToTime(seconds float64) time.Time {
	if seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0).UTC()
}
