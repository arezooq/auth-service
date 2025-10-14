package models

import (
	"time"
)

type User struct {
	ID               string     `json:"id" gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	FName            string     `json:"fname" gorm:"column:f_name"`
	LName            string     `json:"lname" gorm:"column:l_name"`
	Username         string     `json:"username" gorm:"column:user_name;uniqueIndex;not null"`
	Mobile           string     `json:"mobile" gorm:"column:mobile;uniqueIndex"`
	MobileVerifiedAt *time.Time `json:"mobile_verified_at" gorm:"column:mobile_verified_at"`
	Email            string     `json:"email" gorm:"column:email;uniqueIndex"`
	EmailVerifiedAt  *time.Time `json:"email_verified_at" gorm:"column:email_verified_at"`
	Password         string     `json:"password" gorm:"column:password;not null"`
	CreatedBy        string     `json:"created_by" gorm:"column:created_by"`
	CreatedAt        time.Time  `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedBy        string     `json:"updated_by" gorm:"column:updated_by"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	Status           int        `json:"status" gorm:"column:status;not null;default:0"` // -1=deleted, 0=inactive, 1=active
}
