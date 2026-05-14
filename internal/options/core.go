package options

import (
	"fmt"
	"strings"
)

// AWSConnectionOptionsCore contains shared AWS connection settings used by all features.
type AWSConnectionOptionsCore struct {
	Region       string `json:"region"                  title:"Region"        description:"AWS region code used to resolve service endpoints and SigV4 scope."     binding:"required" enum:"us-east-1,us-east-2,us-west-1,us-west-2,af-south-1,ap-east-1,ap-south-2,ap-southeast-3,ap-southeast-5,ap-southeast-4,ap-south-1,ap-southeast-6,ap-northeast-3,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-east-2,ap-southeast-7,ap-northeast-1,ca-central-1,ca-west-1,eu-central-1,eu-west-1,eu-west-2,eu-south-1,eu-west-3,eu-south-2,eu-north-1,eu-central-2,il-central-1,mx-central-1,me-south-1,me-central-1,sa-east-1,us-gov-east-1,us-gov-west-1"`
	SessionToken string `json:"session_token,omitempty" title:"Session Token" description:"AWS session token for temporary credentials such as STS-assumed roles."`
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
	IdentityStoreID string `json:"identity_store_id,omitempty" title:"Identity Store ID" description:"AWS Identity Store identifier used when enumerating Identity Center users and memberships."`
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
