package oauth

import (
	"auth-service/internal/constant"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func getGoogleUserInfo(ctx context.Context, accessToken string) (*constant.OAuthResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://www.googleapis.com/oauth2/v3/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch google user info")
	}

	var data struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &constant.OAuthResponse{
		ID:    data.Sub,
		Email: data.Email,
		Name:  data.Name,
	}, nil
}
