package cache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var (
	// SessionCache stores user sessions with token as key
	// Default expiration: 120 minutes (same as JWT token)
	// Cleanup interval: 10 minutes
	SessionCache = cache.New(120*time.Minute, 10*time.Minute)
)

// SetSession stores a user session in cache with the token as key
func SetSession(token string, userID string, username string, email string) {
	session := map[string]string{
		"userID":   userID,
		"username": username,
		"email":    email,
		"token":    token,
	}
	// Store with expiration matching JWT token expiration (120 minutes)
	SessionCache.Set(token, session, cache.DefaultExpiration)
}

// GetSession retrieves a user session from cache by token
func GetSession(token string) (map[string]string, bool) {
	session, found := SessionCache.Get(token)
	if !found {
		return nil, false
	}
	return session.(map[string]string), true
}

// DeleteSession removes a user session from cache
func DeleteSession(token string) {
	SessionCache.Delete(token)
}
