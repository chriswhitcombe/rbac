package rbac

import (
	"errors"
	"regexp"
	"strings"
)

type RoleMapper struct {
	roleMapping map[string]map[string]roles
}

type roles []string

func NewRoleMapper() *RoleMapper {
	return &RoleMapper{
		roleMapping: make(map[string]map[string]roles),
	}
}

func (rm *RoleMapper) AddMapping(matcher string, r roles) error {
	rm.AddMethodMapping(matcher, "", r)
	return nil
}

func (rm *RoleMapper) AddMethodMapping(matcher, method string, r roles) error {

	if strings.Replace(matcher, " ", "", -1) == "" {
		return errors.New("Matcher must be a non empty string")
	}

	for _, v := range r {
		if len(strings.Split(v, ".")) > 2 {
			return errors.New("RBAC only supported to 2 level roles")
		}
	}

	m := rm.roleMapping[matcher]
	if m == nil {
		m = make(map[string]roles)
	}
	m[method] = r
	rm.roleMapping[matcher] = m
	return nil
}

func getRolesForMatchedPath(rm *RoleMapper, p, method string) (roles, bool) {
	for k, v := range rm.roleMapping {
		//use the path matcher as regex against the current path
		if regexp.MustCompile(k).MatchString(p) {
			//check for correct method
			for k1, v1 := range v {
				if k1 == method {
					return v1, true
				}
			}
		}
	}
	return nil, false
}

func (rm *RoleMapper) RoleValid(p, r string) bool {
	return rm.RoleMethodValid(p, "", r)
}

func (rm *RoleMapper) RoleMethodValid(p, method, r string) bool {
	roles, ok := getRolesForMatchedPath(rm, p, method)
	if !ok {
		return false
	}
	for _, v := range roles {
		//exact matches fine
		if v == r || strings.Split(v, ".")[0] == r {
			return true
		}
	}
	return false
}
