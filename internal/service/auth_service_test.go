package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/consultprompts/auth-service/internal/model"
	"github.com/consultprompts/auth-service/internal/repository"
	"github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

var testPrivateKey *rsa.PrivateKey

func TestMain(m *testing.M) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
	testPrivateKey = key
	os.Exit(m.Run())
}

// --- Mocks ---

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, email, passwordHash string) (*model.User, error) {
	args := m.Called(ctx, email, passwordHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) UpsertGoogleUser(ctx context.Context, email string) (*model.User, bool, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, false, args.Error(2)
	}
	return args.Get(0).(*model.User), args.Bool(1), args.Error(2)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) StoreVerificationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) VerifyEmail(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *MockUserRepository) ReplaceVerificationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) StorePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByPasswordResetToken(ctx context.Context, tokenHash string) (*model.User, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) ResetPassword(ctx context.Context, userID, passwordHash, tokenHash string) error {
	args := m.Called(ctx, userID, passwordHash, tokenHash)
	return args.Error(0)
}

type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.RefreshToken), args.Error(1)
}

func (m *MockTokenRepository) RevokeToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

func (m *MockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) AssignRoleByName(ctx context.Context, userID, roleName string) error {
	args := m.Called(ctx, userID, roleName)
	return args.Error(0)
}

func (m *MockRoleRepository) GetRoleNamesByUserID(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockRoleRepository) RemoveRoleByName(ctx context.Context, userID, roleName string) error {
	args := m.Called(ctx, userID, roleName)
	return args.Error(0)
}

type MockEmailClient struct {
	mock.Mock
}

func (m *MockEmailClient) SendVerificationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailClient) SendPasswordResetEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailClient) SendLoginNotificationEmail(to string) error {
	args := m.Called(to)
	return args.Error(0)
}

// --- Helpers ---

type testMocks struct {
	userRepo  *MockUserRepository
	tokenRepo *MockTokenRepository
	roleRepo  *MockRoleRepository
	email     *MockEmailClient
}

func newTestService() (*AuthService, *testMocks) {
	mocks := &testMocks{
		userRepo:  new(MockUserRepository),
		tokenRepo: new(MockTokenRepository),
		roleRepo:  new(MockRoleRepository),
		email:     new(MockEmailClient),
	}
	svc := NewAuthService(mocks.userRepo, mocks.tokenRepo, mocks.roleRepo, mocks.email, testPrivateKey)
	return svc, mocks
}

func (m *testMocks) assertExpectations(t *testing.T) {
	t.Helper()
	m.userRepo.AssertExpectations(t)
	m.tokenRepo.AssertExpectations(t)
	m.roleRepo.AssertExpectations(t)
	m.email.AssertExpectations(t)
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

func testUser(overrides func(*model.User)) *model.User {
	u := &model.User{
		ID:            "user-123",
		Email:         "user@example.com",
		EmailVerified: true,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if overrides != nil {
		overrides(u)
	}
	return u
}

// isBcryptHashOf returns a matcher that checks the argument is a bcrypt hash of password.
func isBcryptHashOf(password string) interface{} {
	return mock.MatchedBy(func(hash string) bool {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	})
}

func waitForEmail(t *testing.T, sent <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was not sent within timeout", what)
	}
}

// --- Register ---

func TestRegister_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	password := "supersecret123"
	user := testUser(func(u *model.User) { u.EmailVerified = false })

	var storedTokenHash string
	var emailedToken string
	emailSent := make(chan struct{})

	mocks.userRepo.On("CreateUser", ctx, user.Email, isBcryptHashOf(password)).Return(user, nil)
	mocks.roleRepo.On("AssignRoleByName", ctx, user.ID, "student").Return(nil)
	mocks.userRepo.On("StoreVerificationToken", ctx, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { storedTokenHash = args.String(2) }).
		Return(nil)
	mocks.email.On("SendVerificationEmail", user.Email, mock.AnythingOfType("string")).
		Run(func(args mock.Arguments) {
			emailedToken = args.String(1)
			close(emailSent)
		}).
		Return(nil)

	created, err := svc.Register(ctx, user.Email, password)

	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, user.ID, created.ID)
	assert.Equal(t, user.Email, created.Email)

	waitForEmail(t, emailSent, "verification email")
	assert.Equal(t, storedTokenHash, jwt.HashToken(emailedToken),
		"emailed token should hash to the stored verification token hash")

	mocks.assertExpectations(t)
}

func TestRegister_PasswordTooShort(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"seven characters", "1234567"},
		{"empty password", ""},
		{"one character", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mocks := newTestService()

			user, err := svc.Register(context.Background(), "user@example.com", tt.password)

			require.Error(t, err)
			assert.Nil(t, user)
			assert.EqualError(t, err, "password must be at least 8 characters")
			mocks.userRepo.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	mocks.userRepo.On("CreateUser", ctx, "taken@example.com", mock.AnythingOfType("string")).
		Return(nil, &pgconn.PgError{Code: "23505"})

	user, err := svc.Register(ctx, "taken@example.com", "supersecret123")

	require.Error(t, err)
	assert.Nil(t, user)
	assert.EqualError(t, err, "email already registered")
	mocks.roleRepo.AssertNotCalled(t, "AssignRoleByName", mock.Anything, mock.Anything, mock.Anything)
	mocks.assertExpectations(t)
}

// --- Login ---

func TestLogin_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	password := "supersecret123"
	user := testUser(func(u *model.User) { u.PasswordHash = hashPassword(t, password) })
	roles := []string{"student"}

	var storedRefreshHash string

	mocks.userRepo.On("GetUserByEmail", ctx, user.Email).Return(user, nil)
	mocks.roleRepo.On("GetRoleNamesByUserID", ctx, user.ID).Return(roles, nil)
	mocks.tokenRepo.On("RevokeAllUserTokens", ctx, user.ID).Return(nil)
	mocks.tokenRepo.On("StoreRefreshToken", ctx, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { storedRefreshHash = args.String(2) }).
		Return(nil)

	accessToken, refreshToken, err := svc.Login(ctx, user.Email, password)

	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)

	// the stored hash must correspond to the refresh token handed back to the caller
	assert.Equal(t, jwt.HashToken(refreshToken), storedRefreshHash)

	// access token must be a valid RS256 JWT carrying the user's ID and roles
	claims, err := jwt.VerifyToken(accessToken, &testPrivateKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, roles, claims.Roles)

	mocks.assertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	password := "supersecret123"

	tests := []struct {
		name  string
		setup func(t *testing.T, mocks *testMocks)
	}{
		{
			name: "wrong password",
			setup: func(t *testing.T, mocks *testMocks) {
				user := testUser(func(u *model.User) { u.PasswordHash = hashPassword(t, "a-different-password") })
				mocks.userRepo.On("GetUserByEmail", mock.Anything, user.Email).Return(user, nil)
			},
		},
		{
			name: "non-existent email",
			setup: func(t *testing.T, mocks *testMocks) {
				mocks.userRepo.On("GetUserByEmail", mock.Anything, "user@example.com").
					Return(nil, errors.New("no rows in result set"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mocks := newTestService()
			tt.setup(t, mocks)

			accessToken, refreshToken, err := svc.Login(context.Background(), "user@example.com", password)

			require.ErrorIs(t, err, ErrInvalidCredentials)
			assert.Empty(t, accessToken)
			assert.Empty(t, refreshToken)
			mocks.tokenRepo.AssertNotCalled(t, "StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mocks.assertExpectations(t)
		})
	}
}

func TestLogin_EmailNotVerified(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	password := "supersecret123"
	user := testUser(func(u *model.User) {
		u.PasswordHash = hashPassword(t, password)
		u.EmailVerified = false
	})

	mocks.userRepo.On("GetUserByEmail", ctx, user.Email).Return(user, nil)

	accessToken, refreshToken, err := svc.Login(ctx, user.Email, password)

	require.ErrorIs(t, err, ErrEmailNotVerified)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)
	mocks.tokenRepo.AssertNotCalled(t, "StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mocks.assertExpectations(t)
}

// --- RefreshAccessToken ---

func TestRefreshAccessToken_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	oldToken := "old-refresh-token"
	oldHash := jwt.HashToken(oldToken)
	stored := &repository.RefreshToken{
		ID:        "token-1",
		UserID:    "user-123",
		TokenHash: oldHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RevokedAt: nil,
	}
	roles := []string{"student"}

	var newStoredHash string

	mocks.tokenRepo.On("GetByTokenHash", ctx, oldHash).Return(stored, nil)
	mocks.tokenRepo.On("RevokeToken", ctx, oldHash).Return(nil)
	mocks.roleRepo.On("GetRoleNamesByUserID", ctx, stored.UserID).Return(roles, nil)
	mocks.tokenRepo.On("StoreRefreshToken", ctx, stored.UserID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { newStoredHash = args.String(2) }).
		Return(nil)

	accessToken, newRefreshToken, err := svc.RefreshAccessToken(ctx, oldToken)

	require.NoError(t, err)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, newRefreshToken)
	assert.NotEqual(t, oldToken, newRefreshToken, "refresh token must be rotated")
	assert.Equal(t, jwt.HashToken(newRefreshToken), newStoredHash)

	claims, err := jwt.VerifyToken(accessToken, &testPrivateKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, stored.UserID, claims.UserID)
	assert.Equal(t, roles, claims.Roles)

	mocks.assertExpectations(t)
}

func TestRefreshAccessToken_RevokedTokenReuseDetection(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	token := "stolen-refresh-token"
	tokenHash := jwt.HashToken(token)
	revokedAt := time.Now().Add(-time.Hour)
	stored := &repository.RefreshToken{
		ID:        "token-1",
		UserID:    "user-123",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RevokedAt: &revokedAt,
	}

	mocks.tokenRepo.On("GetByTokenHash", ctx, tokenHash).Return(stored, nil)
	mocks.tokenRepo.On("RevokeAllUserTokens", ctx, stored.UserID).Return(nil)

	accessToken, refreshToken, err := svc.RefreshAccessToken(ctx, token)

	require.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)
	// reuse detection must nuke every session for the user
	mocks.tokenRepo.AssertCalled(t, "RevokeAllUserTokens", ctx, stored.UserID)
	mocks.assertExpectations(t)
}

func TestRefreshAccessToken_ExpiredToken(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	token := "expired-refresh-token"
	tokenHash := jwt.HashToken(token)
	stored := &repository.RefreshToken{
		ID:        "token-1",
		UserID:    "user-123",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(-time.Minute),
		RevokedAt: nil,
	}

	mocks.tokenRepo.On("GetByTokenHash", ctx, tokenHash).Return(stored, nil)

	accessToken, refreshToken, err := svc.RefreshAccessToken(ctx, token)

	require.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.Empty(t, accessToken)
	assert.Empty(t, refreshToken)
	mocks.tokenRepo.AssertNotCalled(t, "RevokeToken", mock.Anything, mock.Anything)
	mocks.assertExpectations(t)
}

// --- Logout ---

func TestLogout_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	token := "some-refresh-token"
	mocks.tokenRepo.On("RevokeToken", ctx, jwt.HashToken(token)).Return(nil)

	err := svc.Logout(ctx, token)

	require.NoError(t, err)
	mocks.assertExpectations(t)
}

// --- VerifyEmail ---

func TestVerifyEmail(t *testing.T) {
	tests := []struct {
		name    string
		repoErr error
		wantErr string
	}{
		{name: "valid token", repoErr: nil},
		{name: "invalid token", repoErr: errors.New("invalid or expired verification token"), wantErr: "invalid or expired verification token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mocks := newTestService()
			ctx := context.Background()

			token := "verification-token"
			mocks.userRepo.On("VerifyEmail", ctx, jwt.HashToken(token)).Return(tt.repoErr)

			err := svc.VerifyEmail(ctx, token)

			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			mocks.assertExpectations(t)
		})
	}
}

// --- RequestPasswordReset ---

func TestRequestPasswordReset_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	user := testUser(nil)

	var storedTokenHash string
	var emailedToken string
	emailSent := make(chan struct{})

	mocks.userRepo.On("GetUserByEmail", ctx, user.Email).Return(user, nil)
	mocks.userRepo.On("StorePasswordResetToken", ctx, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { storedTokenHash = args.String(2) }).
		Return(nil)
	mocks.email.On("SendPasswordResetEmail", user.Email, mock.AnythingOfType("string")).
		Run(func(args mock.Arguments) {
			emailedToken = args.String(1)
			close(emailSent)
		}).
		Return(nil)

	err := svc.RequestPasswordReset(ctx, user.Email)

	require.NoError(t, err)
	waitForEmail(t, emailSent, "password reset email")
	assert.Equal(t, storedTokenHash, jwt.HashToken(emailedToken),
		"emailed reset token should hash to the stored token hash")
	mocks.assertExpectations(t)
}

func TestRequestPasswordReset_NonExistentEmailReturnsNil(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	mocks.userRepo.On("GetUserByEmail", ctx, "ghost@example.com").
		Return(nil, errors.New("no rows in result set"))

	err := svc.RequestPasswordReset(ctx, "ghost@example.com")

	// must not leak whether the email is registered
	require.NoError(t, err)
	mocks.userRepo.AssertNotCalled(t, "StorePasswordResetToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mocks.email.AssertNotCalled(t, "SendPasswordResetEmail", mock.Anything, mock.Anything)
	mocks.assertExpectations(t)
}

// --- ResetPassword ---

func TestResetPassword_Success(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	token := "reset-token"
	tokenHash := jwt.HashToken(token)
	newPassword := "brand-new-password"
	user := testUser(nil)

	mocks.userRepo.On("GetUserByPasswordResetToken", ctx, tokenHash).Return(user, nil)
	mocks.tokenRepo.On("RevokeAllUserTokens", ctx, user.ID).Return(nil)
	mocks.userRepo.On("ResetPassword", ctx, user.ID, isBcryptHashOf(newPassword), tokenHash).Return(nil)

	err := svc.ResetPassword(ctx, token, newPassword)

	require.NoError(t, err)
	// all sessions must be revoked so the user is forced to re-login
	mocks.tokenRepo.AssertCalled(t, "RevokeAllUserTokens", ctx, user.ID)
	mocks.assertExpectations(t)
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc, mocks := newTestService()
	ctx := context.Background()

	token := "bogus-token"
	mocks.userRepo.On("GetUserByPasswordResetToken", ctx, jwt.HashToken(token)).
		Return(nil, errors.New("no rows in result set"))

	err := svc.ResetPassword(ctx, token, "brand-new-password")

	require.EqualError(t, err, "Invalid or expired reset token")
	mocks.userRepo.AssertNotCalled(t, "ResetPassword", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mocks.tokenRepo.AssertNotCalled(t, "RevokeAllUserTokens", mock.Anything, mock.Anything)
	mocks.assertExpectations(t)
}

func TestResetPassword_PasswordTooShort(t *testing.T) {
	svc, mocks := newTestService()

	err := svc.ResetPassword(context.Background(), "reset-token", "short")

	require.EqualError(t, err, "Password must be at least 8 characters")
	mocks.userRepo.AssertNotCalled(t, "GetUserByPasswordResetToken", mock.Anything, mock.Anything)
}
