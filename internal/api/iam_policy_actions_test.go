package api

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

const testPolicyArn = "arn:aws:iam::aws:policy/AdministratorAccess"

func TestShouldReturnDefaultVersionIDWhenGetPolicySucceeds(t *testing.T) {
	// Arrange
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GetPolicy", r.PostFormValue("Action"))
		require.Equal(t, testPolicyArn, r.PostFormValue("PolicyArn"))
		fmt.Fprint(w, `<GetPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetPolicyResult>
    <Policy>
      <PolicyName>AdministratorAccess</PolicyName>
      <DefaultVersionId>v3</DefaultVersionId>
    </Policy>
  </GetPolicyResult>
</GetPolicyResponse>`)
	}))

	// Act
	versionID, err := client.GetPolicy(t.Context(), testPolicyArn)

	// Assert
	require.NoError(t, err)
	require.Equal(t, "v3", versionID)
}

func TestShouldExtractAllowedActionsWhenGetPolicyVersionDocumentIsURLEncoded(t *testing.T) {
	// Arrange
	document := url.QueryEscape(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:GetObject"], "Resource": "*"},
			{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
			{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
			{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
		]
	}`)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GetPolicyVersion", r.PostFormValue("Action"))
		require.Equal(t, testPolicyArn, r.PostFormValue("PolicyArn"))
		require.Equal(t, "v3", r.PostFormValue("VersionId"))
		fmt.Fprintf(w, `<GetPolicyVersionResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetPolicyVersionResult>
    <PolicyVersion>
      <Document>%s</Document>
      <VersionId>v3</VersionId>
    </PolicyVersion>
  </GetPolicyVersionResult>
</GetPolicyVersionResponse>`, document)
	}))

	// Act
	actions, err := client.GetPolicyVersion(t.Context(), testPolicyArn, "v3")

	// Assert: Allow actions only, deduplicated and sorted; Deny and NotAction skipped.
	require.NoError(t, err)
	require.Equal(t, []string{"ec2:DescribeInstances", "s3:GetObject", "s3:PutObject"}, actions)
}

func TestShouldExtractAllowedActionsWhenGetRolePolicyReturnsInlineDocument(t *testing.T) {
	// Arrange
	document := url.QueryEscape(`{
		"Version": "2012-10-17",
		"Statement": {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}
	}`)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "GetRolePolicy", r.PostFormValue("Action"))
		require.Equal(t, "worker", r.PostFormValue("RoleName"))
		require.Equal(t, "InlineAccess", r.PostFormValue("PolicyName"))
		fmt.Fprintf(w, `<GetRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetRolePolicyResult>
    <RoleName>worker</RoleName>
    <PolicyName>InlineAccess</PolicyName>
    <PolicyDocument>%s</PolicyDocument>
  </GetRolePolicyResult>
</GetRolePolicyResponse>`, document)
	}))

	// Act
	actions, err := client.GetRolePolicy(t.Context(), "worker", "InlineAccess")

	// Assert
	require.NoError(t, err)
	require.Equal(t, []string{"sqs:SendMessage"}, actions)
}

func TestShouldResolveManagedPolicyActionsWhenPolicyHasDefaultVersion(t *testing.T) {
	// Arrange
	document := url.QueryEscape(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
	}`)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.PostFormValue("Action") {
		case "GetPolicy":
			fmt.Fprint(w, `<GetPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetPolicyResult>
    <Policy><DefaultVersionId>v1</DefaultVersionId></Policy>
  </GetPolicyResult>
</GetPolicyResponse>`)
		case "GetPolicyVersion":
			require.Equal(t, "v1", r.PostFormValue("VersionId"))
			fmt.Fprintf(w, `<GetPolicyVersionResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetPolicyVersionResult>
    <PolicyVersion><Document>%s</Document></PolicyVersion>
  </GetPolicyVersionResult>
</GetPolicyVersionResponse>`, document)
		default:
			t.Fatalf("unexpected IAM action %q", r.PostFormValue("Action"))
		}
	}))

	// Act
	actions, err := client.IAMManagedPolicyActions(t.Context(), testPolicyArn)

	// Assert
	require.NoError(t, err)
	require.Equal(t, []string{"*"}, actions)
}

func TestShouldReturnNilActionsWhenPolicyDocumentHasNoAllowStatements(t *testing.T) {
	require.Nil(t, extractAllowedActions(""))
	require.Nil(t, extractAllowedActions(url.QueryEscape(`{"Statement":[{"Effect":"Deny","Action":"*"}]}`)))
	require.Nil(t, extractAllowedActions("not-json"))
}
