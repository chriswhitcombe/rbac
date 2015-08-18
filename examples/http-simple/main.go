package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/chriswhitcombe/rbac"
	"github.com/chriswhitcombe/rbac/examples/http-simple/userdb"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

func main() {

	//setup a http router (any one would work)
	router := httprouter.New()

	//setup our role mapper
	roleMapper := rbac.NewRoleMapper()

	//setup our 'user db'
	udb := userdb.NewUserDB()
	udb.AddUser("bob", []string{"admin"})
	udb.AddUser("phil", []string{"backoffice", "users.list"})
	udb.AddUser("joan", []string{"viewer"})

	authChain := alice.New(createRBACHandler(udb, roleMapper))

	router.Handler("GET", "/", authChain.Then(urlPage()))
	roleMapper.AddMethodMapping("/admin", "GET", []string{"admin"})
	router.Handler("GET", "/admin", authChain.Then(urlPage()))
	roleMapper.AddMethodMapping("/orders", "GET", []string{"admin", "backoffice", "orders.list"})
	router.Handler("GET", "/orders", authChain.Then(urlPage()))
	roleMapper.AddMethodMapping("/users", "GET", []string{"admin", "users.list"})
	router.Handler("GET", "/users", authChain.Then(urlPage()))
	roleMapper.AddMethodMapping("/news", "GET", []string{"admin", "backoffice", "viewer", "news.list"})
	router.Handler("GET", "/news", authChain.Then(urlPage()))

	log.Fatal(http.ListenAndServe(":8080", router))
}

//simple http middleware to limit access to urls based upon role
func createRBACHandler(udb *userdb.UserDB, rm *rbac.RoleMapper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			//get user from URL (normally you would pull this from OAUTH, a session etc)
			user := r.URL.Query().Get("user")
			roles, ok := udb.GetRoles(user)

			if !ok {
				fmt.Printf("User not found: %s/n", user)
				w.WriteHeader(500)
				return
			}

			if checkForRole(roles, rm, r) {
				next.ServeHTTP(w, r)
			} else {
				fmt.Printf("Access not granted: %s, %s/n", user, r.RequestURI)
				w.WriteHeader(403)
				return
			}
		}
		return http.HandlerFunc(fn)
	}
}

func checkForRole(roles []string, rm *rbac.RoleMapper, r *http.Request) bool {
	for _, v := range roles {
		if rm.RoleMethodValid(r.RequestURI, r.Method, v) {
			return true
		}
	}
	return false
}

//simple http handler just lists what URL you hit
func urlPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "You hit the URL: %s", r.RequestURI)
	})
}
