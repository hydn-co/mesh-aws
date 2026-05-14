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

func (o *AWSCloudTrailActivityCollectorOptions) Validate() error {
	if o == nil {
		return nil
	}

	return o.AWSConnectionOptionsCore.Validate()
}

func (o *AWSSSOLoginActivityCollectorOptions) Validate() error {
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
