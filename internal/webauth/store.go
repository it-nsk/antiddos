// Package webauth stores local web users and revocable, opaque sessions.
package webauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const DefaultPath = "/var/lib/antiddos-web/users.sqlite"
const SessionTTL = 8 * time.Hour
const IdleTTL = 30 * time.Minute

var ErrCredentials = errors.New("invalid username or password")
var ErrSession = errors.New("session expired")
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,64}$`)

type Store struct {
	db    *sql.DB
	dummy []byte
}
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}
type Session struct {
	User      User   `json:"user"`
	CSRF      string `json:"csrf"`
	ExpiresAt int64  `json:"expires_at"`
}

func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("users database path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Create with private permissions before SQLite can write any credentials.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "on")
	q.Set("_journal_mode", "WAL")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS web_users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','viewer')), created_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS web_sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS web_sessions_expiry ON web_sessions(expires_at);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	dummyPassword, err := randomToken()
	if err != nil {
		db.Close()
		return nil, err
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte(dummyPassword), 12)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dummy: dummy}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func hashPassword(password string) ([]byte, error) {
	if len(password) < 12 || len(password) > 72 {
		return nil, fmt.Errorf("password must contain 12–72 bytes")
	}
	return bcrypt.GenerateFromPassword([]byte(password), 12)
}
func (s *Store) Add(ctx context.Context, username, password, role string) error {
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("username: use 1–64 letters, digits, _, ., @ or -")
	}
	if role != "admin" && role != "viewer" {
		return fmt.Errorf("role must be admin or viewer")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO web_users(username,password_hash,role,created_at) VALUES(?,?,?,?)`, username, hash, role, time.Now().Unix())
	return err
}
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,role,created_at FROM web_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
func (s *Store) Delete(ctx context.Context, username string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM web_users WHERE username=?`, username).Scan(&role); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("unknown user")
	} else if err != nil {
		return err
	}
	if role == "admin" {
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM web_users WHERE role='admin'`).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return fmt.Errorf("cannot delete the last administrator")
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM web_users WHERE username=?`, username)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("unknown user")
	}
	return tx.Commit()
}
func (s *Store) Password(ctx context.Context, username, password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE web_users SET password_hash=? WHERE username=?`, hash, username)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("unknown user")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id=(SELECT id FROM web_users WHERE username=?)`, username); err != nil {
		return err
	}
	return tx.Commit()
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
func tokenHash(token string) string {
	v := sha256.Sum256([]byte(token))
	return hex.EncodeToString(v[:])
}
func (s *Store) Login(ctx context.Context, username, password string, now time.Time) (string, Session, error) {
	var u User
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,username,role,created_at,password_hash FROM web_users WHERE username=?`, username).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", Session{}, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		hash = s.dummy
	}
	valid := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	if !valid || u.ID == 0 {
		return "", Session{}, ErrCredentials
	}
	token, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	session := Session{User: u, CSRF: csrf, ExpiresAt: now.Add(SessionTTL).Unix()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", Session{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at<=? OR last_seen<=?`, now.Unix(), now.Add(-IdleTTL).Unix()); err != nil {
		return "", Session{}, err
	}
	var current []byte
	if err := tx.QueryRowContext(ctx, `SELECT password_hash FROM web_users WHERE id=?`, u.ID).Scan(&current); err != nil {
		return "", Session{}, ErrCredentials
	}
	if !bytes.Equal(current, hash) {
		return "", Session{}, ErrCredentials
	}
	// Bound sessions per account without a process-wide in-memory session map.
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM web_sessions WHERE user_id=? ORDER BY last_seen DESC LIMIT 9)`, u.ID, u.ID); err != nil {
		return "", Session{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO web_sessions VALUES(?,?,?,?,?)`, tokenHash(token), u.ID, session.CSRF, session.ExpiresAt, now.Unix()); err != nil {
		return "", Session{}, err
	}
	err = tx.Commit()
	return token, session, err
}
func (s *Store) Authenticate(ctx context.Context, token string, now time.Time) (Session, error) {
	var v Session
	var seen int64
	if len(token) != 64 {
		return v, ErrSession
	}
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.created_at,s.csrf,s.expires_at,s.last_seen
 FROM web_sessions s JOIN web_users u ON u.id=s.user_id WHERE token_hash=? AND expires_at>? AND last_seen>?`, tokenHash(token), now.Unix(), now.Add(-IdleTTL).Unix()).Scan(&v.User.ID, &v.User.Username, &v.User.Role, &v.User.CreatedAt, &v.CSRF, &v.ExpiresAt, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrSession
	}
	if err != nil {
		return v, err
	}
	if now.Unix()-seen >= 60 {
		_, err = s.db.ExecContext(ctx, `UPDATE web_sessions SET last_seen=? WHERE token_hash=?`, now.Unix(), tokenHash(token))
	}
	return v, err
}
func (s *Store) Logout(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash=?`, tokenHash(token))
	return err
}
