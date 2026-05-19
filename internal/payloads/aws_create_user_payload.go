package payloads

// AWSCreateUserPayload carries the parameters for the create user action.
type AWSCreateUserPayload struct {
	UserName string `json:"user_name"      title:"User Name" description:"Name of the IAM user to create (1-64 characters)." binding:"required"`
	Path     string `json:"path,omitempty" title:"Path"      description:"Optional IAM path for the user (defaults to /)."`
}

func (*AWSCreateUserPayload) GetDiscriminator() string {
	return "mesh://aws/actions/create_user_payload"
}
