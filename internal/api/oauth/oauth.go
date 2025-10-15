package oauth

import (
	"auth-service/internal/models"
	"context"

	"github.com/arezooq/open-utils/errors"
)

type OAuthClient interface {
	GetUserInfo(ctx context.Context, provider, accessToken string) (*models.OAuthResponse, error)
}

type oauthClient struct{}

func (c *oauthClient) GetUserInfo(ctx context.Context, provider, accessToken string) (*models.OAuthResponse, error) {
	switch provider {
	case "google":
		return getGoogleUserInfo(ctx, accessToken)
	// case "facebook":
	// 	return getFacebookUserInfo(ctx, accessToken)
	default:
		return nil, errors.ErrInternal
	}
}
