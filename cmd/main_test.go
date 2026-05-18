package main

import (
	"testing"

	"github.com/hydn-co/mesh-sdk/pkg/testkit"
)

func TestDescribe(t *testing.T) {
	testkit.InvokeDescribe(t, WithManifest())
}

func TestList(t *testing.T) {
	testkit.InvokeList(t, WithManifest())
}
