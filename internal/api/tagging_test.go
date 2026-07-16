package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/hydn-co/substrate/enumerators"
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
					{"ResourceARN": "arn:aws:ec2:us-east-1:111111111111:instance/i-0abc", "Tags": [{"Key": "Name", "Value": "web-server"}, {"Key": "env", "Value": "prod"}]},
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
	resources := make([]TaggedResource, 0, 3)
	err := enumerators.ForEach(client.TaggedResourceEnumerator(t.Context()), func(resource TaggedResource) error {
		resources = append(resources, resource)
		return nil
	})

	// Assert
	require.NoError(t, err)
	arns := make([]string, 0, len(resources))
	for _, resource := range resources {
		arns = append(arns, resource.ARN)
	}
	require.Equal(t, []string{
		"arn:aws:ec2:us-east-1:111111111111:instance/i-0abc",
		"arn:aws:s3:::bucket-one",
		"arn:aws:lambda:us-east-1:111111111111:function:fn-one",
	}, arns)
	require.Equal(t, map[string]string{"Name": "web-server", "env": "prod"}, resources[0].Tags)
	require.Empty(t, resources[1].Tags)
	require.Equal(t, []string{"", "page-2"}, requestTokens)
}
