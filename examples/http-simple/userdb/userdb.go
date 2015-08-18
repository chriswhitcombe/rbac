package userdb

type UserDB struct {
	users map[string][]string
}

func NewUserDB() *UserDB {
	return &UserDB{
		make(map[string][]string),
	}
}

func (u *UserDB) AddUser(username string, roles []string) {
	u.users[username] = roles
}

func (u *UserDB) GetRoles(username string) ([]string, bool) {
	roles, ok := u.users[username]
	return roles, ok
}
