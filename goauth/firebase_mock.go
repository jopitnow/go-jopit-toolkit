package goauth

import (
	"context"

	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
)

type FirebaseAccountManagerMock struct {
	HandleVerificationEmail func(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	HandleResetPassword     func(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	HandleSetUserValidated  func(ctx context.Context, uid string, isVerified bool) apierrors.ApiError
	HandleIsUserSubscribed  func(ctx context.Context, uid string) (*string, apierrors.ApiError)
	Spy                     bool
}

func NewFirebaseAccountManagerMock() *FirebaseAccountManagerMock {
	return &FirebaseAccountManagerMock{}
}

func (mock *FirebaseAccountManagerMock) VerificationEmail(ctx context.Context, userEmail string) (string, apierrors.ApiError) {
	mock.Spy = false
	if mock.HandleVerificationEmail != nil {
		mock.Spy = true
		return mock.HandleVerificationEmail(ctx, userEmail)
	}
	return "", nil
}

func (mock *FirebaseAccountManagerMock) ResetPassword(ctx context.Context, userEmail string) (string, apierrors.ApiError) {
	mock.Spy = false
	if mock.HandleResetPassword != nil {
		mock.Spy = true
		return mock.HandleResetPassword(ctx, userEmail)
	}
	return "", nil
}

func (mock *FirebaseAccountManagerMock) SetUserValidated(ctx context.Context, uid string, isVerified bool) apierrors.ApiError {
	mock.Spy = false
	if mock.HandleSetUserValidated != nil {
		mock.Spy = true
		return mock.HandleSetUserValidated(ctx, uid, isVerified)
	}
	return nil
}

func (mock *FirebaseAccountManagerMock) IsUserValidated(ctx context.Context, uid string) (*string, apierrors.ApiError) {
	mock.Spy = false
	if mock.HandleIsUserSubscribed != nil {
		mock.Spy = true
		return mock.HandleIsUserSubscribed(ctx, uid)
	}
	return nil, nil
}
