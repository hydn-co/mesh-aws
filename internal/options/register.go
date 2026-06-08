package options

import "github.com/fgrzl/json/polymorphic"

func init() {
	polymorphic.RegisterType[AWSAccountEntityCollectorOptions]()
	polymorphic.RegisterType[AWSGroupEntityCollectorOptions]()
	polymorphic.RegisterType[AWSRoleEntityCollectorOptions]()
	polymorphic.RegisterType[AWSPolicyEntityCollectorOptions]()
	polymorphic.RegisterType[AWSMFAEntityCollectorOptions]()
	polymorphic.RegisterType[AWSLoginActivityCollectorOptions]()
	polymorphic.RegisterType[AWSCognitoUserPoolAdminActivityCollectorOptions]()
	polymorphic.RegisterType[AWSSessionActivityCollectorOptions]()
	polymorphic.RegisterType[AWSGroupActivityCollectorOptions]()
	polymorphic.RegisterType[AWSGroupMembershipActivityCollectorOptions]()
	polymorphic.RegisterType[AWSRoleActivityCollectorOptions]()
	polymorphic.RegisterType[AWSEntitlementActivityCollectorOptions]()
	polymorphic.RegisterType[AWSAccountActivityCollectorOptions]()
	polymorphic.RegisterType[AWSOrganizationEntityCollectorOptions]()
	polymorphic.RegisterType[AWSSecretEntityCollectorOptions]()
	polymorphic.RegisterType[AWSAddUserToGroupActionOptions]()
	polymorphic.RegisterType[AWSCreateUserActionOptions]()
	polymorphic.RegisterType[AWSCreateGroupActionOptions]()
}
