package payloads

import (
	"time"

	"github.com/fgrzl/json/polymorphic"
)

func init() {
	polymorphic.RegisterType[DisableUserPayload]()
	polymorphic.RegisterType[AddUserToGroupPayload]()
	polymorphic.RegisterType[RemoveUserFromGroupPayload]()
	polymorphic.RegisterType[ActivityResumePayload]()
}

// DisableUserPayload carries the target user reference for the disable-user action.
type DisableUserPayload struct {
	UserName string `json:"user_name"`
}

func (*DisableUserPayload) GetDiscriminator() string { return "mesh://aws/payloads/disable-user" }

// AddUserToGroupPayload carries the user and group references for the add-to-group action.
type AddUserToGroupPayload struct {
	UserName  string `json:"user_name"`
	GroupName string `json:"group_name"`
}

func (*AddUserToGroupPayload) GetDiscriminator() string {
	return "mesh://aws/payloads/add-user-to-group"
}

// RemoveUserFromGroupPayload carries the user and group references for the remove-from-group action.
type RemoveUserFromGroupPayload struct {
	UserName  string `json:"user_name"`
	GroupName string `json:"group_name"`
}

func (*RemoveUserFromGroupPayload) GetDiscriminator() string {
	return "mesh://aws/payloads/remove-user-from-group"
}

// ActivityResumePayload carries the last event timestamp for activity resume.
type ActivityResumePayload struct {
	LastEventTime *time.Time `json:"last_event_time,omitempty"`
}

func (*ActivityResumePayload) GetDiscriminator() string {
	return "mesh://aws/payloads/activity-resume"
}
