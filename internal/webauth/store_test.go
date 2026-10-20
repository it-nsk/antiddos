package webauth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionsAndRevocation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Add(ctx, "admin", "long-enough-password", "admin"); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := s.db.QueryRow(`SELECT password_hash FROM web_users`).Scan(&hash); err != nil || hash == "long-enough-password" {
		t.Fatal("password not hashed", err)
	}
	now := time.Now()
	token, session, err := s.Login(ctx, "admin", "long-enough-password", now)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || session.User.Role != "admin" || session.CSRF == "" {
		t.Fatal(session)
	}
	var stored string
	s.db.QueryRow(`SELECT token_hash FROM web_sessions`).Scan(&stored)
	if stored == token {
		t.Fatal("raw token persisted")
	}
	if _, err := s.Authenticate(ctx, token, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, now.Add(IdleTTL+2*time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("idle timeout", err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Authenticate(ctx, token, now.Add(2*time.Minute)); err != nil {
		t.Fatal("session did not survive restart", err)
	}
	if err := s.Password(ctx, "admin", "replacement-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, now); !errors.Is(err, ErrSession) {
		t.Fatal("password change did not revoke session")
	}
	token, _, err = s.Login(ctx, "admin", "replacement-password", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, now); !errors.Is(err, ErrSession) {
		t.Fatal("logout failed")
	}
	token, _, err = s.Login(ctx, "admin", "replacement-password", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "second-admin", "long-enough-password", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, now); !errors.Is(err, ErrSession) {
		t.Fatal("deletion failed to revoke session")
	}
}

func TestCannotDeleteLastAdministrator(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "users.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Add(ctx, "admin", "long-enough-password", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "viewer", "long-enough-password", "viewer"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "admin"); err == nil {
		t.Fatal("last administrator was deleted")
	}
	users, err := s.Users(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("users after rejected delete: %v, %v", users, err)
	}
	if err := s.Delete(ctx, "viewer"); err != nil {
		t.Fatal(err)
	}
}
func TestCredentialsAndValidation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "users.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Add(ctx, "bad space", "long-enough-password", "admin"); err == nil {
		t.Fatal("invalid username accepted")
	}
	if err := s.Add(ctx, "user", "short", "viewer"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.Add(ctx, "user", "long-enough-password", "root"); err == nil {
		t.Fatal("invalid role")
	}
	if err := s.Add(ctx, "user", "long-enough-password", "viewer"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "user"} {
		if _, _, err := s.Login(ctx, name, "incorrect-password", time.Now()); !errors.Is(err, ErrCredentials) {
			t.Fatal(err)
		}
	}
	token, _, err := s.Login(ctx, "user", "long-enough-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token, time.Now().Add(SessionTTL+time.Second)); !errors.Is(err, ErrSession) {
		t.Fatal("absolute timeout not enforced")
	}
}
