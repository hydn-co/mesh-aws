package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/fgrzl/enumerators"
	"github.com/stretchr/testify/require"
)

func TestShouldPaginateTaggedResourcesWhenGetResourcesReturnsToken(t *testing.T) {
	// Arrange
	requestTokens := make([]string, 0, 2)
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, taggingGetResources, r.Header.Get("X-Amz-Target"))

		var request map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		token, _ := request["PaginationToken"].(string)
		requestTokens = append(requestTokens, token)

		if token == "" {
			fmt.Fprint(w, `{
				"PaginationToken": "page-2",
				"ResourceTagMappingList": [
					{"ResourceARN": "arn:aws:ec2:us-east-1:111111111111:instance/i-0abc"},
					{"ResourceARN": "arn:aws:s3:::bucket-one"}
				]
			}`)
			return
		}
		require.Equal(t, "page-2", token)
		fmt.Fprint(w, `{
			"PaginationToken": "",
			"ResourceTagMappingList": [
				{"ResourceARN": "arn:aws:lambda:us-east-1:111111111111:function:fn-one"}
			]
		}`)
	}))

	// Act
	arns := make([]string, 0, 3)
	err := enumerators.ForEach(client.TaggedResourceEnumerator(t.Context()), func(resource TaggedResource) error {
		arns = append(arns, resource.ARN)
		return nil
	})

	// Assert
	require.NoError(t, err)
	require.Equal(t, []string{
		"arn:aws:ec2:us-east-1:111111111111:instance/i-0abc",
		"arn:aws:s3:::bucket-one",
		"arn:aws:lambda:us-east-1:111111111111:function:fn-one",
	}, arns)
	require.Equal(t, []string{"", "page-2"}, requestTokens)
}
