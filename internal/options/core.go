package options

import (
	"fmt"
	"strings"
)

// AWSConnectionOptionsCore contains shared AWS connection settings used by all features.
type AWSConnectionOptionsCore struct {
	Region       string `json:"region"                  title:"Region"        description:"AWS region used to resolve service endpoints and SigV4 scope."`
	SessionToken string `json:"session_token,omitempty" title:"Session Token" description:"AWS session token for temporary credentials."`
}

func (o *AWSConnectionOptionsCore) GetRegion() string {
	if o == nil {
		return ""
	}

	return strings.TrimSpace(o.Region)
}

func (o *AWSConnectionOptionsCore) GetSessionToken() string {
	if o == nil {
		return ""
	}

	return strings.TrimSpace(o.SessionToken)
}

func (o *AWSConnectionOptionsCore) Validate() error {
	if o == nil {
		return nil
	}

	if o.GetRegion() == "" {
		return fmt.Errorf("region is required")
	}

	return nil
}

// AWSIdentityStoreOptionsCore contains the optional Identity Store identifier shared by account and group collectors.
type AWSIdentityStoreOptionsCore struct {
	IdentityStoreID string `json:"identity_store_id" title:"Identity Store ID" description:"AWS Identity Store identifier used when enumerating Identity Center users and memberships."`
}

func (o *AWSIdentityStoreOptionsCore) GetIdentityStoreID() string {
	if o == nil {
		return ""
	}

	return strings.TrimSpace(o.IdentityStoreID)
}

func (o *AWSIdentityStoreOptionsCore) Validate() error {
	return nil
}
