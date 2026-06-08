package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldParseListAccountsResponse(t *testing.T) {
	body := []byte(`{
		"Accounts": [
			{"Id":"111111111111","Arn":"arn:aws:organizations::999:account/o-x/111111111111","Email":"a@example.com","Name":"workload","Status":"ACTIVE","JoinedTimestamp":1700000000}
		],
		"NextToken": "next-page"
	}`)

	var resp listAccountsResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.Len(t, resp.Accounts, 1)
	require.Equal(t, "next-page", resp.NextToken)

	account := resp.Accounts[0].toAccount()
	require.Equal(t, "111111111111", account.ID)
	require.Equal(t, "workload", account.Name)
	require.Equal(t, "ACTIVE", account.Status)
	require.False(t, account.JoinedTimestamp.IsZero())
}

func TestShouldParseListOrganizationalUnitsResponse(t *testing.T) {
	body := []byte(
		`{"OrganizationalUnits":[{"Id":"ou-abc","Arn":"arn:aws:organizations::999:ou/o-x/ou-abc","Name":"Workloads"}]}`,
	)

	var resp listOUsResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	require.Len(t, resp.OrganizationalUnits, 1)

	ou := resp.OrganizationalUnits[0].toOrganizationalUnit()
	require.Equal(t, "ou-abc", ou.ID)
	require.Equal(t, "Workloads", ou.Name)
}

func TestShouldBuildRequestBodyWithAndWithoutToken(t *testing.T) {
	withToken := requestBodyWithToken(map[string]any{"ParentId": "ou-abc"}, "tok")
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(withToken, &parsed))
	require.Equal(t, "ou-abc", parsed["ParentId"])
	require.Equal(t, "tok", parsed["NextToken"])

	empty := requestBodyWithToken(nil, "")
	require.JSONEq(t, "{}", string(empty))
}
