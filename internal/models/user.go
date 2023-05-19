package models

// User model
type User struct {
	ID        uint   `gorm:"primarykey"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	AvatarURL string `json:"avatar_url"`
}

type Waitlist struct {
	Email     string `json:"email"`
	ID        uint   `gorm:"primarykey"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}
