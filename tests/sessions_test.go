package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// TestDBSessions @notice The store's security properties against a real Postgres: fixation
// (rotation kills the planted token), immediate revocation, both expiries, the account-disable
// join, and the bounded last_seen write.
//
// @param t the test handle
func TestDBSessions(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	// Schema set explicitly even though the pool's search_path already points there: this is
	// the Config.TableSchema path, and the tests are where it earns its keep.
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}

	uid := createUser(t, db, "owner@example.com")
	if _, err := db.Exec(`insert into auth_roles (name) values ('admin'), ('editor')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into auth_user_roles (user_id, role) values (?, 'editor'), (?, 'admin')`, uid, uid); err != nil {
		t.Fatal(err)
	}

	t.Run("issue and lookup", func(t *testing.T) {
		token, err := s.Issue(ctx, db, uid, session.Meta{UserAgent: "tests/1.0", IP: "10.1.2.3"})
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 43 {
			t.Errorf("token length = %d, want 43 (32 bytes, base64url)", len(token))
		}
		p, err := s.Lookup(ctx, db, token)
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			t.Fatal("a live session resolved to anonymous")
		}
		if p.UserID != uid || p.Email != "owner@example.com" || !p.Verified {
			t.Errorf("principal = %+v", p)
		}
		if len(p.Roles) != 2 || p.Roles[0] != "admin" || p.Roles[1] != "editor" {
			t.Errorf("roles = %v, want [admin editor] sorted", p.Roles)
		}
		if p.SessionID == "" || p.AuthAt.IsZero() {
			t.Errorf("session identity missing: %+v", p)
		}
		if !p.MFAAt.IsZero() {
			t.Errorf("MFAAt = %v, want zero on a fresh session", p.MFAAt)
		}
	})

	t.Run("unknown token is anonymous, not an error", func(t *testing.T) {
		p, err := s.Lookup(ctx, db, "no-such-token-at-all")
		if err != nil || p != nil {
			t.Errorf("Lookup(garbage) = %v, %v — want nil, nil", p, err)
		}
	})

	t.Run("rotation swaps the credential and kills the old one", func(t *testing.T) {
		old, err := s.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		p1, err := s.Lookup(ctx, db, old)
		if err != nil || p1 == nil {
			t.Fatal(err)
		}
		fresh, err := s.Rotate(ctx, db, p1.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, old); p != nil {
			t.Error("the pre-rotation token still resolves — session fixation is alive")
		}
		p2, err := s.Lookup(ctx, db, fresh)
		if err != nil || p2 == nil {
			t.Fatal("the rotated token does not resolve")
		}
		if p2.SessionID != p1.SessionID {
			t.Error("rotation changed the session identity")
		}
		if !p2.AuthAt.Equal(p1.AuthAt) {
			t.Error("rotation moved AuthAt — the absolute lifetime just stopped being absolute")
		}
	})

	t.Run("rotating a dead session is UNAUTHENTICATED", func(t *testing.T) {
		token, err := s.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		p, _ := s.Lookup(ctx, db, token)
		if err := s.Revoke(ctx, db, p.SessionID); err != nil {
			t.Fatal(err)
		}
		_, err = s.Rotate(ctx, db, p.SessionID)
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("Rotate(dead) = %v, want UNAUTHENTICATED", err)
		}
	})

	t.Run("revocation is immediate", func(t *testing.T) {
		token, _ := s.Issue(ctx, db, uid, session.Meta{})
		p, _ := s.Lookup(ctx, db, token)
		if err := s.Revoke(ctx, db, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, token); p != nil {
			t.Error("a revoked session still resolves")
		}
		if err := s.Revoke(ctx, db, p.SessionID); err != nil {
			t.Errorf("second Revoke = %v, want idempotent nil", err)
		}
	})

	t.Run("revoke all", func(t *testing.T) {
		a, _ := s.Issue(ctx, db, uid, session.Meta{})
		b, _ := s.Issue(ctx, db, uid, session.Meta{})
		if err := s.RevokeAllForUser(ctx, db, uid); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, a); p != nil {
			t.Error("session a survived revoke-all")
		}
		if p, _ := s.Lookup(ctx, db, b); p != nil {
			t.Error("session b survived revoke-all")
		}
	})

	t.Run("disabling the account drops its sessions at lookup", func(t *testing.T) {
		u := createUser(t, db, "disabled@example.com")
		token, _ := s.Issue(ctx, db, u, session.Meta{})
		if _, err := db.Exec(`update auth_users set deleted_at = now() where id = ?`, u); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, token); p != nil {
			t.Error("a disabled account's session still resolves — the deleted_at join is gone")
		}
	})

	t.Run("idle and absolute expiry", func(t *testing.T) {
		token, _ := s.Issue(ctx, db, uid, session.Meta{})
		p, _ := s.Lookup(ctx, db, token)
		if _, err := db.Exec(`update auth_sessions set idle_expires_at = now() - interval '1 second' where id = ?`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, token); p != nil {
			t.Error("an idle-expired session still resolves")
		}

		token2, _ := s.Issue(ctx, db, uid, session.Meta{})
		p2, _ := s.Lookup(ctx, db, token2)
		if _, err := db.Exec(`update auth_sessions set expires_at = now() - interval '1 second' where id = ?`, p2.SessionID); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Lookup(ctx, db, token2); p != nil {
			t.Error("an absolutely-expired session still resolves")
		}
	})

	t.Run("last_seen refresh is bounded to 60s granularity", func(t *testing.T) {
		token, _ := s.Issue(ctx, db, uid, session.Meta{})
		p, _ := s.Lookup(ctx, db, token)

		var seen1 time.Time
		if _, err := db.QueryOne(pg.Scan(&seen1), `select last_seen_at from auth_sessions where id = ?`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Lookup(ctx, db, token); err != nil {
			t.Fatal(err)
		}
		var seen2 time.Time
		if _, err := db.QueryOne(pg.Scan(&seen2), `select last_seen_at from auth_sessions where id = ?`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if !seen2.Equal(seen1) {
			t.Errorf("a lookup within 60s wrote last_seen_at (%v → %v) — one read became one write", seen1, seen2)
		}

		// Age the row past the granularity window; the next lookup must refresh both fields.
		if _, err := db.Exec(`update auth_sessions
		       set last_seen_at = now() - interval '2 minutes',
		           idle_expires_at = now() + interval '1 minute'
		     where id = ?`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Lookup(ctx, db, token); err != nil {
			t.Fatal(err)
		}
		var seen3 time.Time
		var idle3 time.Time
		if _, err := db.QueryOne(pg.Scan(&seen3, &idle3),
			`select last_seen_at, idle_expires_at from auth_sessions where id = ?`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if !seen3.After(seen1) {
			t.Error("an aged session's lookup did not refresh last_seen_at")
		}
		if until := time.Until(idle3); until < 11*time.Hour {
			t.Errorf("idle window refreshed to only %v out — want ~12h", until)
		}
	})

	t.Run("list shows live sessions, newest first", func(t *testing.T) {
		u := createUser(t, db, "lister@example.com")
		tokA, _ := s.Issue(ctx, db, u, session.Meta{UserAgent: "A", IP: "not-an-ip"})
		if _, err := s.Issue(ctx, db, u, session.Meta{UserAgent: "B", IP: "192.0.2.7"}); err != nil {
			t.Fatal(err)
		}
		pA, _ := s.Lookup(ctx, db, tokA)
		if _, err := db.Exec(`update auth_sessions set last_seen_at = now() - interval '5 minutes' where id = ?`, pA.SessionID); err != nil {
			t.Fatal(err)
		}

		infos, err := s.List(ctx, db, u)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 2 {
			t.Fatalf("List = %d sessions, want 2", len(infos))
		}
		if infos[0].UserAgent != "B" || infos[1].UserAgent != "A" {
			t.Errorf("order = [%s %s], want most recent first", infos[0].UserAgent, infos[1].UserAgent)
		}
		if infos[0].IP != "192.0.2.7" {
			t.Errorf("IP = %q", infos[0].IP)
		}
		if infos[1].IP != "" {
			t.Errorf("an unparseable IP should store NULL, got %q", infos[1].IP)
		}

		if err := s.Revoke(ctx, db, pA.SessionID); err != nil {
			t.Fatal(err)
		}
		infos, _ = s.List(ctx, db, u)
		if len(infos) != 1 || infos[0].UserAgent != "B" {
			t.Errorf("after revoking A, List = %+v", infos)
		}
	})
}
