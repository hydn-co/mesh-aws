package api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldParseAssumeRoleCredentials(t *testing.T) {
	body := []byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>AKIA_TEMP</AccessKeyId>
      <SecretAccessKey>temp-secret</SecretAccessKey>
      <SessionToken>temp-token</SessionToken>
      <Expiration>2026-06-04T18:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`)

	var resp assumeRoleResp
	require.NoError(t, xml.Unmarshal(body, &resp))
	require.Equal(t, "AKIA_TEMP", resp.Result.Credentials.AccessKeyID)
	require.Equal(t, "temp-secret", resp.Result.Credentials.SecretAccessKey)
	require.Equal(t, "temp-token", resp.Result.Credentials.SessionToken)
	require.Equal(t, "2026-06-04T18:00:00Z", resp.Result.Credentials.Expiration)
}

func TestShouldReturnAccountWhenGetCallerIdentitySucceeds(t *testing.T) {
	// Arrange
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GetCallerIdentity", r.PostFormValue("Action"))
		fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/collector</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`)
	}))

	// Act
	accountID, err := client.GetCallerIdentity(t.Context())

	// Assert
	require.NoError(t, err)
	require.Equal(t, "123456789012", accountID)
}

func TestShouldParseSTSErrorBody(t *testing.T) {
	body := []byte(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>not authorized to perform sts:AssumeRole</Message>
  </Error>
</ErrorResponse>`)

	err := parseSTSError(body, 403)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AccessDenied")
	require.Contains(t, err.Error(), "403")
}
