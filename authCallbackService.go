package nats_auth_callout

import (
	"fmt"
	"log/slog"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	AuthCalloutSubject = "$SYS.REQ.USER.AUTH"
)

var (
	logger = slog.Default().With("logger", "nats-auth-callout")
)

type AuthorizationResult struct {
	Account              string
	UserPermissionLimits *jwt.UserPermissionLimits
	Expires              int64
}

type AuthCallbackService struct {
	keyPair  nkeys.KeyPair
	callback AuthCallback
}

type AuthCallback func(req *jwt.AuthorizationRequestClaims) (*AuthorizationResult, error)

func NewAuthCallbackService(keyPair nkeys.KeyPair, callback AuthCallback) *AuthCallbackService {
	return &AuthCallbackService{
		keyPair:  keyPair,
		callback: callback,
	}
}

func (service *AuthCallbackService) Register(nc *nats.Conn) (*nats.Subscription, error) {
	return nc.Subscribe(AuthCalloutSubject, service.HandleMessage)
}

func (service *AuthCallbackService) HandleMessage(msg *nats.Msg) {
	authorizationRequestClaims, err := jwt.DecodeAuthorizationRequestClaims(string(msg.Data))
	if err != nil {
		logger.Error("failed to parse authorization request claims JWT",
			"err", err,
		)
		return
	}

	authorizationResult, err := service.callback(authorizationRequestClaims)
	if err != nil {
		logger.Error("authorization error",
			"err", err,
		)
		service.sendResponse(msg, authorizationRequestClaims.UserNkey, authorizationRequestClaims.Server.ID, "", fmt.Errorf("authorization error: %w", err))
		return
	}

	userClaims := jwt.NewUserClaims(authorizationRequestClaims.UserNkey)
	userClaims.Name = authorizationRequestClaims.ConnectOptions.Username
	userClaims.Audience = authorizationResult.Account
	userClaims.Expires = authorizationResult.Expires
	if authorizationResult.UserPermissionLimits != nil {
		userClaims.UserPermissionLimits = *authorizationResult.UserPermissionLimits
	}
	userClaimsJwt, err := userClaims.Encode(service.keyPair)
	if err != nil {
		logger.Error("failed to encode user claims JWT",
			"err", err,
		)
		service.sendResponse(msg, authorizationRequestClaims.UserNkey, authorizationRequestClaims.Server.ID, "", fmt.Errorf("failed to encode user claims JWT: %w", err))
		return
	}

	service.sendResponse(msg, authorizationRequestClaims.UserNkey, authorizationRequestClaims.Server.ID, userClaimsJwt, nil)
}

func (service *AuthCallbackService) sendResponse(msg *nats.Msg, subject string, audience string, uJwt string, err error) {
	authorizationResponseClaims := jwt.NewAuthorizationResponseClaims(subject)
	authorizationResponseClaims.Audience = audience
	authorizationResponseClaims.Jwt = uJwt
	if err != nil {
		authorizationResponseClaims.Error = err.Error()
	}

	authorizationResponseClaimsJwt, err := authorizationResponseClaims.Encode(service.keyPair)
	if err != nil {
		logger.Error("failed to encode authorization response claims JWT",
			"err", err,
		)
		return
	}

	err = msg.Respond([]byte(authorizationResponseClaimsJwt))
	if err != nil {
		logger.Error("failed to send authorization response claims",
			"err", err,
		)
		return
	}
}
