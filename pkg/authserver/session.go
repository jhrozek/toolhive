package authserver

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

// Session extends fosite's JWT session with an IDP session reference.
// This allows the authorization server to link issued tokens to
// upstream IDP tokens stored separately.
type Session struct {
	*oauth2.JWTSession

	// IDPSessionID links this session to stored upstream IDP tokens.
	// This ID is used to retrieve the IDP tokens from storage.
	IDPSessionID string
}

// NewSession creates a new Session with the given subject and IDP session ID.
func NewSession(subject, idpSessionID string) *Session {
	return &Session{
		JWTSession: &oauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Subject: subject,
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
		IDPSessionID: idpSessionID,
	}
}

// Clone creates a deep copy of the session.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	var jwtSession *oauth2.JWTSession
	if s.JWTSession != nil {
		if cloned := s.JWTSession.Clone(); cloned != nil {
			if js, ok := cloned.(*oauth2.JWTSession); ok {
				jwtSession = js
			}
		}
	}

	return &Session{
		JWTSession:   jwtSession,
		IDPSessionID: s.IDPSessionID,
	}
}

// SetExpiresAt sets the expiration time for a specific token type.
func (s *Session) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.JWTSession == nil {
		s.JWTSession = &oauth2.JWTSession{}
	}
	s.JWTSession.SetExpiresAt(key, exp)
}

// GetExpiresAt returns the expiration time for a specific token type.
func (s *Session) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.JWTSession == nil {
		return time.Time{}
	}
	return s.JWTSession.GetExpiresAt(key)
}

// GetSubject returns the subject of the session.
func (s *Session) GetSubject() string {
	if s.JWTSession == nil || s.JWTClaims == nil {
		return ""
	}
	return s.JWTClaims.Subject
}

// SetSubject sets the subject of the session.
func (s *Session) SetSubject(subject string) {
	if s.JWTSession == nil {
		s.JWTSession = &oauth2.JWTSession{}
	}
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	s.JWTClaims.Subject = subject
}

// GetUsername returns the username of the session.
func (s *Session) GetUsername() string {
	if s.JWTSession == nil {
		return ""
	}
	return s.Username
}

// SetUsername sets the username of the session.
func (s *Session) SetUsername(username string) {
	if s.JWTSession == nil {
		s.JWTSession = &oauth2.JWTSession{}
	}
	s.Username = username
}

// GetJWTClaims returns the JWT claims for this session.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTSession == nil {
		return nil
	}
	return s.JWTSession.GetJWTClaims()
}

// GetJWTHeader returns the JWT header for this session.
func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.JWTSession == nil {
		return nil
	}
	return s.JWTSession.GetJWTHeader()
}

// SetIDPSessionID sets the IDP session ID.
func (s *Session) SetIDPSessionID(id string) {
	s.IDPSessionID = id
}

// GetIDPSessionID returns the IDP session ID.
func (s *Session) GetIDPSessionID() string {
	return s.IDPSessionID
}
