package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	FName            string     `json:"fname" gorm:"column:f_name"`
	LName            string     `json:"lname" gorm:"column:l_name"`
	Username         string     `json:"username" gorm:"column:user_name;uniqueIndex;not null"`
	Mobile           string     `json:"mobile" gorm:"column:mobile;uniqueIndex"`
	MobileVerifiedAt *time.Time `json:"mobile_verified_at" gorm:"column:mobile_verified_at"`
	Email            string     `json:"email" gorm:"column:email;uniqueIndex"`
	EmailVerifiedAt  *time.Time `json:"email_verified_at" gorm:"column:email_verified_at"`
	Password         string     `gorm:"column:password;not null"`
	CityID           *uuid.UUID `json:"city_id" gorm:"column:city_id"`
	StateID          *uuid.UUID `json:"state_id" gorm:"column:state_id"`
	CountryID        *uuid.UUID `json:"country_id" gorm:"column:country_id"`
	ReferralCode     string     `json:"referral_code" gorm:"column:referral_code"`
	ReferralCount    int        `json:"referral_count" gorm:"column:referral_count;default:0"`
	ReferredBy       *uuid.UUID `json:"referred_by" gorm:"column:referred_by"`
	SelectedAccount  *uuid.UUID `json:"selected_account" gorm:"column:selected_account"`
	IsInternational  bool       `json:"is_international" gorm:"column:is_international;default:false"`
	NationalNumber   string     `json:"national_number" gorm:"column:national_number"`
	Status           int        `json:"status" gorm:"column:status;not null;default:0"`
	CreatedAt        time.Time  `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}
