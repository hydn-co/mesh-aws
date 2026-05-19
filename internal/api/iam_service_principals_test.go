package api

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldExtractServicePrincipalsFromAllowAssumeRoleStatements(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","ecs.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`

	principals := extractServicePrincipals(url.QueryEscape(policy))

	require.ElementsMatch(t, []string{"lambda.amazonaws.com", "ecs.amazonaws.com"}, principals)
}

func TestShouldIgnoreServicePrincipalsWhenActionIsNotAssumeRole(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:TagSession"}]}`

	principals := extractServicePrincipals(url.QueryEscape(policy))

	require.Nil(t, principals)
}

func TestShouldIgnoreServicePrincipalsWhenEffectIsNotAllow(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	principals := extractServicePrincipals(url.QueryEscape(policy))

	require.Nil(t, principals)
}

func TestShouldHandleMixedStatementsAndDeduplicate(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","ecs.amazonaws.com"]},"Action":["sts:AssumeRole","sts:TagSession"]},{"Effect":"Deny","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	principals := extractServicePrincipals(url.QueryEscape(policy))

	require.ElementsMatch(t, []string{"lambda.amazonaws.com", "ecs.amazonaws.com"}, principals)
}
