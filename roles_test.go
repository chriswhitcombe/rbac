package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddSingle(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test", "GET", []string{"admin", "tester"})
	assert.True(t, rm.RoleMethodValid("/test", "GET", "admin"), "Role should be valid")
}

func TestNoMapping(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test", "GET", []string{"admin", "tester"})
	assert.False(t, rm.RoleMethodValid("/d", "GET", "admin"), "Role should be invalid")
}

func TestIncorrectMethod(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test", "GET", []string{"admin", "tester"})
	assert.False(t, rm.RoleMethodValid("/test", "POST", "admin"), "Method should be missing")
}

func TestWildcardMapping(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test/.*", "GET", []string{"admin", "tester"})
	assert.True(t, rm.RoleMethodValid("/test/asdas2321j", "GET", "admin"), "Role should be valid")
}

func TestWildcardMappingFailure(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test/b.*", "GET", []string{"admin", "tester"})
	assert.False(t, rm.RoleMethodValid("/test/aaa", "GET", "admin"), "Path should not match")
}

func TestNoMethodMapping(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMapping("/test", []string{"admin", "tester"})
	assert.True(t, rm.RoleValid("/test", "admin"), "Path should match")
}

func TestExactDotMapping(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test", "POST", []string{"tester.add"})
	assert.True(t, rm.RoleMethodValid("/test", "POST", "tester.add"), "Path should match")
	assert.False(t, rm.RoleMethodValid("/test", "POST", "tester.delete"), "Path should not match")
}

func TestParentDotMapping(t *testing.T) {
	rm := NewRoleMapper()
	rm.AddMethodMapping("/test", "POST", []string{"tester.add"})
	assert.True(t, rm.RoleMethodValid("/test", "POST", "tester"), "Path should match")
	assert.False(t, rm.RoleMethodValid("/test", "POST", "user"), "Path should not match")
}

func TestLayeredDotMapping(t *testing.T) {
	rm := NewRoleMapper()
	err := rm.AddMethodMapping("/test", "POST", []string{"tester.file.create"})
	assert.NotNil(t, err, "Triple nested roles should not be allowed")
}

func TestEmptyMatcher(t *testing.T) {
	rm := NewRoleMapper()
	err := rm.AddMethodMapping("", "POST", []string{"tester.file"})
	assert.NotNil(t, err, "Matcher must be non empty string")
}

func TestSpaceMatcher(t *testing.T) {
	rm := NewRoleMapper()
	err := rm.AddMethodMapping("            ", "POST", []string{"tester.file"})
	assert.NotNil(t, err, "Matcher must be non empty string")
}
