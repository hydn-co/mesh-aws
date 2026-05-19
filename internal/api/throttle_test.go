package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldClassifyAWSThrottleErrorsAcrossCommonAWSShapes(t *testing.T) {
	tests := []struct {
		err  error
		name string
		want bool
	}{
		{
			name: "cloudtrail throttling exception",
			err:  errors.New(`cloudtrail HTTP 400: {"__type":"ThrottlingException","message":"Rate exceeded"}`),
			want: true,
		},
		{name: "iam throttling code", err: errors.New("iam Throttling: Rate exceeded (HTTP 400)"), want: true},
		{
			name: "identity store 429",
			err:  errors.New(`identitystore HTTP 429: {"message":"TooManyRequestsException"}`),
			want: true,
		},
		{name: "request limit exceeded", err: errors.New("iam RequestLimitExceeded: slow down (HTTP 400)"), want: true},
		{name: "non throttle", err: errors.New("iam NoSuchEntity: not found (HTTP 404)"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAWSThrottleError(tt.err))
		})
	}
}
