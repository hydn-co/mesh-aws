package api

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldExtractAWSPrincipalsFromAllowAssumeRoleStatements(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","arn:aws:iam::123456789012:user/alice"]},"Action":"sts:AssumeRole"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.ElementsMatch(t, []string{
		"arn:aws:iam::123456789012:root",
		"arn:aws:iam::123456789012:user/alice",
	}, principals)
}

func TestShouldExtractSingleStringAWSPrincipal(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"},"Action":"sts:AssumeRole"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.Equal(t, []string{"arn:aws:iam::123456789012:role/app"}, principals)
}

func TestShouldSkipWildcardAWSPrincipal(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.Nil(t, principals)
}

func TestShouldSkipNonIAMARNAWSPrincipal(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:s3:::example-bucket","arn:aws:iam::123456789012:user/bob"]},"Action":"sts:AssumeRole"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.Equal(t, []string{"arn:aws:iam::123456789012:user/bob"}, principals)
}

func TestShouldIgnoreAWSPrincipalsWhenEffectIsNotAllow(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.Nil(t, principals)
}

func TestShouldIgnoreAWSPrincipalsWhenActionIsNotAssumeRole(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:TagSession"}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.Nil(t, principals)
}

func TestShouldDeduplicateAWSPrincipalsAcrossStatements(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","arn:aws:iam::999999999999:role/peer"]},"Action":["sts:AssumeRole"]}]}`

	principals := extractAWSPrincipals(url.QueryEscape(policy))

	require.ElementsMatch(t, []string{
		"arn:aws:iam::123456789012:root",
		"arn:aws:iam::999999999999:role/peer",
	}, principals)
}

func TestShouldExtractOnlyAWSPrincipalsWhenServiceAndAWSAreMixed(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com","AWS":"arn:aws:iam::123456789012:user/alice"},"Action":"sts:AssumeRole"}]}`

	require.Equal(t, []string{"arn:aws:iam::123456789012:user/alice"}, extractAWSPrincipals(url.QueryEscape(policy)))
	require.Equal(t, []string{"lambda.amazonaws.com"}, extractServicePrincipals(url.QueryEscape(policy)))
}
