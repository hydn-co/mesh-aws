package api

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	taggingEndpoint     = "https://tagging.%s.amazonaws.com/"
	taggingService      = "tagging"
	taggingGetResources = "ResourceGroupsTaggingAPI_20170126.GetResources"

	// taggingResourcesPerPage is the maximum page size GetResources accepts.
	taggingResourcesPerPage = 100
)

// TaggedResource is one resource ARN returned by the Resource Groups Tagging
// API. The API is the lowest-setup inventory source AWS offers (one permission,
// no recorder or index to enable), but it only returns resources that are or
// once were tagged — never-tagged resources are invisible to it.
type TaggedResource struct {
	ARN string
}

type taggingResourceMappingJSON struct {
	ResourceARN string `json:"ResourceARN"`
}

type getResourcesResponse struct {
	PaginationToken        string                       `json:"PaginationToken"`
	ResourceTagMappingList []taggingResourceMappingJSON `json:"ResourceTagMappingList"`
}

func (c *Client) taggingPost(ctx context.Context, target string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf(taggingEndpoint, c.region)
	return c.awsJSONPost(ctx, endpoint, target, taggingService, body)
}

// GetResources returns one page of tagged-resource ARNs in the client's region.
// Pass an empty token for the first page; the returned token is empty when done.
func (c *Client) GetResources(ctx context.Context, paginationToken string) ([]TaggedResource, string, error) {
	request := map[string]any{"ResourcesPerPage": taggingResourcesPerPage}
	if paginationToken != "" {
		request["PaginationToken"] = paginationToken
	}
	body, _ := json.Marshal(request)

	data, err := c.taggingPost(ctx, taggingGetResources, body)
	if err != nil {
		return nil, "", fmt.Errorf("get resources: %w", err)
	}

	var resp getResourcesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", fmt.Errorf("parse get resources response: %w", err)
	}

	resources := make([]TaggedResource, len(resp.ResourceTagMappingList))
	for i, m := range resp.ResourceTagMappingList {
		resources[i] = TaggedResource{ARN: m.ResourceARN}
	}
	return resources, resp.PaginationToken, nil
}
