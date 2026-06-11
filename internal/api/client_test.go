package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// rewriteTransport redirects the client's fixed AWS endpoints to a local
// httptest server so signed requests can be served by canned handlers.
type rewriteTransport struct {
	host string
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.host
	return http.DefaultTransport.RoundTrip(req)
}

// newTestClient returns a Client whose HTTP traffic is served by handler.
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewClient(&AWSCredentials{
		AccessKeyID:     "AKIA_TEST",
		SecretAccessKey: "test-secret",
	}, "us-east-1", "")
	require.NoError(t, err)
	client.http.Transport = rewriteTransport{host: server.Listener.Addr().String()}
	return client
}
