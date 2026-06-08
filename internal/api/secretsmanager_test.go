package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldParseListSecretsResponse(t *testing.T) {
	body := []byte(`{
		"SecretList": [
			{
				"ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:db-creds-AbCdEf",
				"Name": "db-creds",
				"KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/abc",
				"OwningService": "rds",
				"RotationEnabled": true,
				"RotationLambdaARN": "arn:aws:lambda:us-east-1:111111111111:function:rotate",
				"LastChangedDate": 1700000000,
				"Tags": [{"Key":"env","Value":"prod"}]
			}
		],
		"NextToken": ""
	}`)

	var resp listSecretsResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.Len(t, resp.SecretList, 1)

	secret := resp.SecretList[0].toSecret()
	require.Equal(t, "arn:aws:secretsmanager:us-east-1:111111111111:secret:db-creds-AbCdEf", secret.ARN)
	require.Equal(t, "db-creds", secret.Name)
	require.Equal(t, "rds", secret.OwningService)
	require.True(t, secret.RotationEnabled)
	require.Equal(t, "prod", secret.Tags["env"])
	require.False(t, secret.LastChangedDate.IsZero())
}

func TestShouldReturnZeroTimeForAbsentEpoch(t *testing.T) {
	require.True(t, epochSecondsToTime(0).IsZero())
	require.False(t, epochSecondsToTime(1700000000).IsZero())
}
