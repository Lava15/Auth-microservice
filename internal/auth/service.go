package auth

import (
	"context"
	"errors"
	"github.com/lava15/Auth-microservice/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
	"sync"
)

type AuthService struct {
	users      map[string]string
	mu         sync.RWMutex
	jwtManager *jwt.JWTManager
}

func NewAuthService(jwtManager *jwt.JWTManager) *AuthService {
	return &AuthService{
		users:      make(map[string]string),
		jwtManager: jwtManager,
	}
}

func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[req.Username]; exists {
		return nil, errors.New("user already exists")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password).bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	s.users[req.Username] = string(hashedPassword)
	return &RegisterResponse{Message: "User registered!"}
}
