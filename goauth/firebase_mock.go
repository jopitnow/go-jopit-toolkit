package goauth

import (
	"context"

	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
)

type FirebaseAccountManagerMock struct {
	HandleVerificationEmail      func(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	HandleResetPassword          func(ctx context.Context, userEmail string) (string, apierrors.ApiError)
	HandleSetUserValidated       func(ctx context.Context, uid string, isVerified bool) apierrors.ApiError
	HandleIsUserValidated        func(ctx context.Context, uid string) (bool, apierrors.ApiError)
	HandleSetUserSubscribed      func(ctx context.Context, uid string, subscription string) apierrors.ApiError
	HandleIsUserSubscribed       func(ctx context.Context, uid string) (*string, apierrors.ApiError)
	HandleRemoveUserSubscription func(ctx context.Context, uid string) apierrors.ApiError
	Spy                          bool
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

func (mock *FirebaseAccountManagerMock) IsUserValidated(ctx context.Context, uid string) (bool, apierrors.ApiError) {
	mock.Spy = false
	if mock.HandleIsUserValidated != nil {
		mock.Spy = true
		return mock.HandleIsUserValidated(ctx, uid)
	}
	return false, nil
}

func (mock *FirebaseAccountManagerMock) SetUserSubscribed(ctx context.Context, uid string, subscription string) apierrors.ApiError {
	mock.Spy = false
	if mock.HandleSetUserSubscribed != nil {
		mock.Spy = true
		return mock.HandleSetUserSubscribed(ctx, uid, subscription)
	}
	return nil
}

func (mock *FirebaseAccountManagerMock) IsUserSubscribed(ctx context.Context, uid string) (*string, apierrors.ApiError) {
	mock.Spy = false
	if mock.HandleIsUserSubscribed != nil {
		mock.Spy = true
		return mock.HandleIsUserSubscribed(ctx, uid)
	}
	return nil, nil
}

func (mock *FirebaseAccountManagerMock) RemoveUserSubscription(ctx context.Context, uid string) apierrors.ApiError {
	mock.Spy = false
	if mock.HandleRemoveUserSubscription != nil {
		mock.Spy = true
		return mock.HandleRemoveUserSubscription(ctx, uid)
	}
	return nil
}
