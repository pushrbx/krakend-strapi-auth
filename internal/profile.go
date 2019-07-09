package internal

type userProfileJson struct {
	Username  string       `json:"username"`
	Id        int32        `json:"id"`
	Email     string       `json:"email"`
	Provider  string       `json:"provider"`
	Confirmed bool         `json:"confirmed"`
	Blocked   interface{}  `json:"blocked,omitempty"`
	Role      userRoleJson `json:"role"`
	CreatedAt string       `json:"created_at"`
	UpdatedAt string       `json:"updated_at"`
}

type userRoleJson struct {
	Id          int32  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

type UserProfile struct {
	Username  string
	Id        int32
	Email     string
	Provider  string
	Confirmed bool
	Blocked   interface{}
	Role      StrapiRole
	CreatedAt string
	UpdatedAt string
}

type StrapiRole struct {
	Id          int32
	Name        string
	Description string
	Type        string
}
