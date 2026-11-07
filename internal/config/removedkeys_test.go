package config

import (
	"reflect"
	"testing"
)

// RemovedKeys is the removed-key table's names, sorted, for the docs lint (tests/ci): a page must
// never teach a key the loader refuses.
func TestRemovedKeysNamesTheRefusedKeys(t *testing.T) {
	want := []string{"key_refs", "password_env", "secret_env"}
	if got := RemovedKeys(); !reflect.DeepEqual(got, want) {
		t.Errorf("RemovedKeys() = %v, want %v", got, want)
	}
}
