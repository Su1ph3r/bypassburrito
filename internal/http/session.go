package http

import (
	"sync"
)

// Session manages HTTP session state
type Session struct {
	mu      sync.RWMutex
	headers map[string]string
	cookies map[string]string
}

// NewSession creates a new session
func NewSession() *Session {
	return &Session{
		headers: make(map[string]string),
		cookies: make(map[string]string),
	}
}

// SetHeader sets a header
func (s *Session) SetHeader(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers[key] = value
}

// GetHeader gets a header
func (s *Session) GetHeader(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.headers[key]
}

// RemoveHeader removes a header
func (s *Session) RemoveHeader(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.headers, key)
}

// Headers returns all headers
func (s *Session) Headers() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.headers))
	for k, v := range s.headers {
		result[k] = v
	}
	return result
}

// SetCookie sets a cookie
func (s *Session) SetCookie(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookies[name] = value
}

// GetCookie gets a cookie
func (s *Session) GetCookie(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cookies[name]
}

// RemoveCookie removes a cookie
func (s *Session) RemoveCookie(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cookies, name)
}

// Cookies returns all cookies
func (s *Session) Cookies() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.cookies))
	for k, v := range s.cookies {
		result[k] = v
	}
	return result
}

// ClearCookies removes all cookies
func (s *Session) ClearCookies() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookies = make(map[string]string)
}

// ClearHeaders removes all headers
func (s *Session) ClearHeaders() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = make(map[string]string)
}

// Clear removes all session data
func (s *Session) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = make(map[string]string)
	s.cookies = make(map[string]string)
}

// Clone creates a copy of the session
func (s *Session) Clone() *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newSession := NewSession()
	for k, v := range s.headers {
		newSession.headers[k] = v
	}
	for k, v := range s.cookies {
		newSession.cookies[k] = v
	}
	return newSession
}
