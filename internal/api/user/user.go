package user

import (
	"auth-service/internal/models"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type UserClient struct {
    baseURL string
    client  *http.Client
}

func NewUserClient(baseURL string) *UserClient {
    return &UserClient{
        baseURL: baseURL,
        client: &http.Client{Timeout: 5 * time.Second},
    }
}

func (uc *UserClient) GetUserByEmail(email string) (*models.User, error) {
    url := fmt.Sprintf("%s/users/by-email/%s", uc.baseURL, email)

    resp, err := uc.client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("user not found")
    }

    var user *models.User
    if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
        return nil, err
    }

    return user, nil
}

func (c *UserClient) Create(req *models.User) error {
	body, _ := json.Marshal(req)
	resp, err := http.Post(c.baseURL+"/users", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Failed to create user")
	}
	return nil
}

func (uc *UserClient) Update(userID uuid.UUID, updates map[string]any) error {
	url := fmt.Sprintf("%s/users/%s", uc.baseURL, userID)
	body, _ := json.Marshal(updates)

	reqHTTP, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := uc.client.Do(reqHTTP)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to update user, status: %d", resp.StatusCode)
	}
	return nil
}