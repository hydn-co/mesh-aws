package api

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldParseListAttachedRolePoliciesResponse(t *testing.T) {
	body := []byte(`
<ListAttachedRolePoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAttachedRolePoliciesResult>
    <AttachedPolicies>
      <member>
        <PolicyName>AdministratorAccess</PolicyName>
        <PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn>
      </member>
      <member>
        <PolicyName>ReadOnlyAccess</PolicyName>
        <PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn>
      </member>
    </AttachedPolicies>
    <IsTruncated>false</IsTruncated>
  </ListAttachedRolePoliciesResult>
</ListAttachedRolePoliciesResponse>`)

	var resp listAttachedRolePoliciesResp
	require.NoError(t, xml.Unmarshal(body, &resp))

	require.False(t, resp.Result.IsTruncated)
	require.Len(t, resp.Result.AttachedPolicies.Members, 2)
	require.Equal(t, "AdministratorAccess", resp.Result.AttachedPolicies.Members[0].PolicyName)
	require.Equal(t, "arn:aws:iam::aws:policy/AdministratorAccess", resp.Result.AttachedPolicies.Members[0].PolicyArn)
}

func TestShouldParseListRolePoliciesResponse(t *testing.T) {
	body := []byte(`
<ListRolePoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListRolePoliciesResult>
    <PolicyNames>
      <member>InlineAccess</member>
      <member>SecondInline</member>
    </PolicyNames>
    <IsTruncated>false</IsTruncated>
  </ListRolePoliciesResult>
</ListRolePoliciesResponse>`)

	var resp listRolePoliciesResp
	require.NoError(t, xml.Unmarshal(body, &resp))

	require.False(t, resp.Result.IsTruncated)
	require.Equal(t, []string{"InlineAccess", "SecondInline"}, resp.Result.PolicyNames.Members)
}
