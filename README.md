# rbac

[![Build Status](https://travis-ci.org/chriswhitcombe/rbac.svg?branch=master)](https://travis-ci.org/chriswhitcombe/rbac)
[![Coverage Status](https://coveralls.io/repos/chriswhitcombe/rbac/badge.svg?branch=master&service=github)](https://coveralls.io/github/chriswhitcombe/rbac?branch=master)
[![Build Status](https://godoc.org/github.com/chriswhitcombe/rbac?status.svg)](https://godoc.org/github.com/chriswhitcombe/rbac)

--
    import "github.com/chriswhitcombe/rbac"

Package rbac is a simple role based access control api for golang http servers.

## Overview
There are 3 elements to role based access control, users, roles and resources. This package consists of functions to limit access to resources by role, it does not handle user to role mapping (i.e. how you map from a specific user to their roles).

## Usage

RBAC has been modelled in a similar way to the standard http libraries, to instantiate a mapper simply run:

```go
roleMapper := rbac.NewRoleMapper()
```

You can then add mappings, usually from paths to roles as such:

```go
roleMapper.AddMethodMapping("/admin", "GET", []string{"admin"})
roleMapper.AddMethodMapping("/products", "GET", []string{"admin", "products.list"})
roleMapper.AddMethodMapping("/products", "POST", []string{"admin", "products.create"})
```

The final step is to lookup a users roles, and validate they are able to access a resource, see the http example for doing this nicely in a http middleware chain:

```go
for _, role := range usersRoles {
  if rm.RoleValid(path, method, role) {
    return true
  }
}
```

## Examples

### HTTP-Simple
The http simple example shows the use of RBAC as a http handler with a static user DB, this demonstrates a normal use case of wanting to lock out certain parts of a website based upon user roles.
