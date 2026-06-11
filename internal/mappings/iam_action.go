// Package mappings normalizes AWS-native identifiers (IAM action strings, ARNs)
// into the provider-agnostic catalog taxonomies owned by the connector.
package mappings

import (
	"strings"

	"github.com/hydn-co/mesh-sdk/pkg/catalog/types"
)

// awsActionVerbPrefixes maps lowercased IAM action-name prefixes onto a
// normalized CRUDE verb. Prefixes are matched longest-first against the action
// name (the part after "service:"), so e.g. "Disassociate" wins over "Disable"
// territory and "Reboot" is never shadowed by "Read". Keys are sorted by verb,
// then alphabetically.
var awsActionVerbPrefixes = map[string]types.PermissionType{
	// Create
	"allocate": types.PermissionCreate,
	"create":   types.PermissionCreate,

	// Read
	"describe": types.PermissionRead,
	"get":      types.PermissionRead,
	"head":     types.PermissionRead,
	"list":     types.PermissionRead,
	"lookup":   types.PermissionRead,
	"query":    types.PermissionRead,
	"read":     types.PermissionRead,
	"receive":  types.PermissionRead,
	"scan":     types.PermissionRead,
	"search":   types.PermissionRead,
	"select":   types.PermissionRead,
	"view":     types.PermissionRead,

	// Edit
	"add":          types.PermissionEdit,
	"associate":    types.PermissionEdit,
	"attach":       types.PermissionEdit,
	"deregister":   types.PermissionEdit,
	"detach":       types.PermissionEdit,
	"disable":      types.PermissionEdit,
	"disassociate": types.PermissionEdit,
	"enable":       types.PermissionEdit,
	"modify":       types.PermissionEdit,
	"put":          types.PermissionEdit,
	"register":     types.PermissionEdit,
	"set":          types.PermissionEdit,
	"tag":          types.PermissionEdit,
	"untag":        types.PermissionEdit,
	"update":       types.PermissionEdit,

	// Delete
	"delete":    types.PermissionDelete,
	"purge":     types.PermissionDelete,
	"remove":    types.PermissionDelete,
	"terminate": types.PermissionDelete,

	// Execute
	"assume":  types.PermissionExecute,
	"cancel":  types.PermissionExecute,
	"execute": types.PermissionExecute,
	"invoke":  types.PermissionExecute,
	"publish": types.PermissionExecute,
	"reboot":  types.PermissionExecute,
	"restart": types.PermissionExecute,
	"run":     types.PermissionExecute,
	"send":    types.PermissionExecute,
	"start":   types.PermissionExecute,
	"stop":    types.PermissionExecute,
}

// MapAWSActionPermissionType maps an IAM action string ("s3:GetObject") onto a
// normalized CRUDE verb using the leading operation verb of its action name.
// AWS action names follow a Verb+Noun convention ("GetObject", "DeleteBucket"),
// so the verb is resolved by longest-prefix, case-insensitive match against a
// curated prefix table. A trailing "*" is stripped first so partial wildcards
// keep their verb ("s3:Get*" → Read).
//
// Wildcards covering many verbs at once ("*", "s3:*") can't be a single CRUDE
// value, so they map to PermissionUnknown — the action string is still recorded
// on the Permission. Unrecognized verbs also map to PermissionUnknown.
func MapAWSActionPermissionType(action string) types.PermissionType {
	action = strings.TrimSpace(action)
	if action == "" || action == "*" {
		return types.PermissionUnknown
	}

	name := action
	if _, after, found := strings.Cut(action, ":"); found {
		name = after
	}
	name = strings.ToLower(strings.TrimSuffix(name, "*"))
	if name == "" {
		return types.PermissionUnknown
	}

	matched := ""
	verb := types.PermissionUnknown
	for prefix, permissionType := range awsActionVerbPrefixes {
		if len(prefix) > len(matched) && strings.HasPrefix(name, prefix) {
			matched = prefix
			verb = permissionType
		}
	}
	return verb
}
