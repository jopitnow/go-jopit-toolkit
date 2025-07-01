package goauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
	"google.golang.org/api/option"
)

type headerKey string

const (
	UserIDMock                            = "TEST-MOCK-USER"
	FirebaseAuthHeader  firebaseHeaderKey = "Authorization"
	FirebaseUserID      firebaseUserID    = "user_id"
	userValidationKey   string            = "kyc_verified"
	userSubscriptionKey string            = "subscription_active"
	lastSubscriptionKey string            = "last_subscription_id"
)

var (
	fbClient *firebaseClient
	once     sync.Once
)

type firebaseHeaderKey string
type firebaseUserID string

type firebaseCredential struct {
	Type                    string `json:"type"`
	ProjectId               string `json:"project_id"`
	PrivateKeyId            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientId                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
}

type firebaseClient struct {
	AuthClient *auth.Client
}

// init initiates the firebase client ONCE
func init() {
	once.Do(InitFirebase)
}

func InitFirebase() {

	opt := option.WithCredentialsJSON([]byte(os.Getenv("FIREBASE_CREDENTIALS")))
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Println("Error connecting to firebase" + err.Error())
	}

	authClient, errAuth := app.Auth(context.Background())
	if errAuth != nil {
		log.Println("Error connecting to firebase" + errAuth.Error())
	}

	fbClient = &firebaseClient{
		AuthClient: authClient,
	}
}

/* func GetEmailFromUserID(c *gin.Context) (string, error) {

	userID, exist := c.Get("user_id")
	if !exist {
		return "", fmt.Errorf("expected to receive an user_id, but it was empty")
	}

	userRecord, err := fbClient.AuthClient.GetUser(c, userID.(string))
	if err != nil {
		return "", err
	}

	userEmail := userRecord.UserInfo.Email

	return userEmail, nil
} */

func AuthWithFirebase() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			err := fmt.Errorf("missing Authorization Header")
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		idToken := strings.TrimSpace(strings.Replace(header, "Bearer", "", 1))
		decodedToken, err := fbClient.AuthClient.VerifyIDToken(context.Background(), idToken)
		if err != nil {
			c.Error(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		c.Set("user_id", decodedToken.UID)
		c.Next()
	}
}

func CheckFirebaseCredentials() error {
	var fields []string
	firebaseCredentials := firebaseCredential{}

	bytes, err := ioutil.ReadFile("./config/credentials.json")
	if err != nil {
		return fmt.Errorf("file not found")
	}

	err = json.Unmarshal(bytes, &firebaseCredentials)
	if err != nil {
		return fmt.Errorf("error unmarshalling the credentials")
	}

	if firebaseCredentials.Type == "" {
		fields = append(fields, "type is nil")
	}
	if firebaseCredentials.ProjectId == "" {
		fields = append(fields, "projectId is nil")
	}
	if firebaseCredentials.PrivateKeyId == "" {
		fields = append(fields, "privateKeyId is nil")
	}
	if firebaseCredentials.PrivateKey == "" {
		fields = append(fields, "privateKey is nil")
	}
	if firebaseCredentials.ClientEmail == "" {
		fields = append(fields, "clientEmail is nil")
	}
	if firebaseCredentials.ClientId == "" {
		fields = append(fields, "clientId is nil")
	}
	if firebaseCredentials.AuthUri == "" {
		fields = append(fields, "authUri is nil")
	}
	if firebaseCredentials.TokenUri == "" {
		fields = append(fields, "tokenUri is nil")
	}
	if firebaseCredentials.AuthProviderX509CertUrl == "" {
		fields = append(fields, "authProviderX509CertUrl is nil")
	}
	if firebaseCredentials.ClientX509CertUrl == "" {
		fields = append(fields, "clientX509CertUrl is nil")
	}

	if len(fields) != 0 {
		return fmt.Errorf("some credentials values are nil: %s", fields)
	}
	return nil
}

func GetUserId(c *gin.Context) (string, apierrors.ApiError) {
	userID, exist := c.Get("user_id")
	if !exist {
		return "", apierrors.NewApiError("user_id is empty", "unauthorized", http.StatusUnauthorized, apierrors.CauseList{})
	}
	return userID.(string), nil
}

func MockAuthWithFirebase() gin.HandlerFunc {
	return func(c *gin.Context) {

		userID := c.GetHeader("Authorization")
		if userID == "" {
			userID = UserIDMock
		}

		c.Set("user_id", userID)
		c.Next()
	}
}

type firebaseAccountManager struct {
	AuthClient *auth.Client
}

func NewFirebaseAccountManager() FirebaseAccountManager {
	return firebaseAccountManager{AuthClient: fbClient.AuthClient}
}

type FirebaseAccountManager interface {
	VerificationEmail(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	ResetPassword(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	SetUserValidated(ctx context.Context, uid string, isVerified bool) apierrors.ApiError
	IsUserValidated(ctx context.Context, uid string) (bool, apierrors.ApiError)
	IsUserSubscribed(ctx context.Context, uid string) (bool, *string, apierrors.ApiError)
	SetUserSubscription(ctx context.Context, uid string, subscription string) apierrors.ApiError
	RemoveUserSubscription(ctx context.Context, uid string) apierrors.ApiError
}

func (fam firebaseAccountManager) VerificationEmail(ctx context.Context, userEmail string) (string, apierrors.ApiError) {

	link, err := fam.AuthClient.EmailVerificationLink(ctx, userEmail)
	if err != nil {
		return "", apierrors.NewApiError("error on firebase verification . ", "TK_13", http.StatusInternalServerError, apierrors.CauseList{err.Error()})
	}

	return link, nil
}

func (fam firebaseAccountManager) ResetPassword(ctx context.Context, userEmail string) (string, apierrors.ApiError) {

	link, err := fam.AuthClient.PasswordResetLink(ctx, userEmail)
	if err != nil {
		return "", apierrors.NewApiError("error on firebase PasswordResetLink. ", "TK_14", http.StatusInternalServerError, apierrors.CauseList{err.Error()})
	}

	return link, nil
}

func (fam firebaseAccountManager) SetUserValidated(ctx context.Context, uid string, isVerified bool) apierrors.ApiError {
	err := fam.updateCustomClaims(ctx, uid, map[string]interface{}{userValidationKey: isVerified})
	if err != nil {
		return apierrors.NewApiError(
			"error on firebase user validation. ",
			"set_custom_user_claims",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	return nil
}

func (fam firebaseAccountManager) IsUserValidated(ctx context.Context, uid string) (bool, apierrors.ApiError) {
	user, err := fam.AuthClient.GetUser(ctx, uid)
	if err != nil {
		return false, apierrors.NewApiError(
			"error on firebase user validation.",
			"get_user_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	if value, ok := user.CustomClaims[userValidationKey].(bool); ok {
		return value, nil
	}

	return false, nil
}

func (fam firebaseAccountManager) SetUserSubscription(ctx context.Context, uid string, subscription string) apierrors.ApiError {
	claims := map[string]interface{}{
		userSubscriptionKey: true,
		lastSubscriptionKey: subscription,
	}

	err := fam.updateCustomClaims(ctx, uid, claims)
	if err != nil {
		return apierrors.NewApiError(
			"error on firebase subscription settle.",
			"set_subscription_status_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	return nil
}

func (fam firebaseAccountManager) IsUserSubscribed(ctx context.Context, uid string) (bool, *string, apierrors.ApiError) {
	user, err := fam.AuthClient.GetUser(ctx, uid)
	if err != nil {
		return false, nil, apierrors.NewApiError(
			"error on firebase subscription status.",
			"subscription_status_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	subscribed, ok := user.CustomClaims[userSubscriptionKey].(bool)
	if !ok {
		return false, nil, nil
	}

	lastId, ok := user.CustomClaims[lastSubscriptionKey].(string)
	if !ok {
		return subscribed, nil, nil
	}

	return subscribed, &lastId, nil
}

func (fam firebaseAccountManager) RemoveUserSubscription(ctx context.Context, uid string) apierrors.ApiError {
	claims := map[string]interface{}{userSubscriptionKey: false}

	err := fam.updateCustomClaims(ctx, uid, claims)
	if err != nil {
		return apierrors.NewApiError(
			"error removing user subscription.",
			"remove_subscription_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	return nil
}

func (fam firebaseAccountManager) updateCustomClaims(ctx context.Context, uid string, updates map[string]interface{}) apierrors.ApiError {
	user, err := fam.AuthClient.GetUser(ctx, uid)
	if err != nil {
		return apierrors.NewApiError(
			"failed to retrieve user",
			"get_user_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	claims := make(map[string]interface{})
	for k, v := range user.CustomClaims {
		claims[k] = v
	}

	for k, v := range updates {
		claims[k] = v
	}

	err = fbClient.AuthClient.SetCustomUserClaims(ctx, uid, claims)
	if err != nil {
		return apierrors.NewApiError(
			"failed to update custom claims",
			"set_custom_claims_error",
			http.StatusInternalServerError,
			apierrors.CauseList{err.Error()},
		)
	}

	return nil
}

func NewServiceGetEmailFromUserID() GetEmailFromUserID {
	return &getEmailFromUserId{}
}

type getEmailFromUserId struct {
	GetEmailFromUserIDInterface GetEmailFromUserID
}

type GetEmailFromUserID interface {
	GetEmailFromUserID(ctx context.Context) (string, apierrors.ApiError)
	GetEmailByUserID(ctx context.Context, uid string) (string, apierrors.ApiError)
}

func (e getEmailFromUserId) GetEmailFromUserID(ctx context.Context) (string, apierrors.ApiError) {

	userID := ctx.Value(FirebaseUserID)
	if userID == nil {
		return "", apierrors.NewApiError("error retrieving userID from the context, its emopty!", "internal_server_error", http.StatusInternalServerError, apierrors.CauseList{})
	}

	userRecord, err := fbClient.AuthClient.GetUser(ctx, userID.(string))
	if err != nil {
		return "", apierrors.NewApiError(err.Error(), "internal_server_error", http.StatusInternalServerError, apierrors.CauseList{})
	}

	userEmail := userRecord.UserInfo.Email

	return userEmail, nil
}

func (e getEmailFromUserId) GetEmailByUserID(ctx context.Context, uid string) (string, apierrors.ApiError) {
	userRecord, err := fbClient.AuthClient.GetUser(ctx, uid)
	if err != nil {
		return "", apierrors.NewApiError(err.Error(), "internal_server_error", http.StatusInternalServerError, apierrors.CauseList{})
	}

	userEmail := userRecord.UserInfo.Email

	return userEmail, nil
}

type JopitUser struct {
	UID         string `json:"rawId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	PhotoURL    string `json:"photoUrl,omitempty"`
}

func NewServiceGetUserInformation() GetUserInformation {
	return &userService{}
}

type userService struct {
	GetUserInformationInterface GetUserInformation
}

type GetUserInformation interface {
	GetUserInformation(ctx context.Context) (JopitUser, error)
}

func (s userService) GetUserInformation(ctx context.Context) (JopitUser, error) {
	userID := ctx.Value(FirebaseUserID)
	if userID == "" {
		return JopitUser{}, fmt.Errorf("expected to receive an user_id, but it was empty")
	}

	user, err := fbClient.AuthClient.GetUser(ctx, userID.(string))
	if err != nil {
		return JopitUser{}, err
	}

	return JopitUser{
		UID:         user.UID,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		PhotoURL:    user.PhotoURL,
	}, nil
}
