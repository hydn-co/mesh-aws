package options

func (o *AWSAccountEntityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	if err := o.AWSConnectionOptionsCore.Validate(); err != nil {
		return err
	}
	return o.AWSIdentityStoreOptionsCore.Validate()
}

func (o *AWSGroupEntityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	if err := o.AWSConnectionOptionsCore.Validate(); err != nil {
		return err
	}
	return o.AWSIdentityStoreOptionsCore.Validate()
}

func (o *AWSRoleEntityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSPolicyEntityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSMFAEntityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSLoginActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSCognitoUserPoolAdminActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSSessionActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSGroupActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSGroupMembershipActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSRoleActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSEntitlementActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSAccountActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSAddUserToGroupActionOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSCreateUserActionOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSCreateGroupActionOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}
