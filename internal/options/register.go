package options

import "github.com/fgrzl/json/polymorphic"

func init() {
	polymorphic.RegisterType[AWSAccountEntityCollectorOptions]()
	polymorphic.RegisterType[AWSGroupEntityCollectorOptions]()
	polymorphic.RegisterType[AWSRoleEntityCollectorOptions]()
	polymorphic.RegisterType[AWSPolicyEntityCollectorOptions]()
	polymorphic.RegisterType[AWSMFAEntityCollectorOptions]()
	polymorphic.RegisterType[AWSCloudTrailActivityCollectorOptions]()
	polymorphic.RegisterType[AWSSSOLoginActivityCollectorOptions]()
	polymorphic.RegisterType[AWSAddUserToGroupActionOptions]()
}
