package helpers

import "fmt"

// CheckInitialized returns an error if Init was not called before Start or Stop.
func CheckInitialized(initialized bool) error {
	if !initialized {
		return fmt.Errorf("feature not initialized; call Init first")
	}
	return nil
}
