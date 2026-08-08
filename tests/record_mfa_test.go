package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// mfaAt @notice The stored mfa_at for one session, or the zero time when it is null.
//
// @dev Every test below asserts on the column rather than on a return value, because the failure
// worth catching is a RecordMFA that returns an error and writes the row anyway — which a test
// asserting only on the error passes.
func mfaAt(t *testing.T, db *pg.DB, sessionID string) time.Time {
	t.Helper()
	var at pg.NullTime
	if _, err := db.QueryOne(pg.Scan(&at),
		`select mfa_at from auth_sessions where id = ?`, sessionID); err != nil {
		t.Fatal(err)
	}
	return at.Time
}

// TestDBRecordMFA @notice The three ways a second factor must not be recordable, and the one way
// it must.
//
// @param t the test handle
func TestDBRecordMFA(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}

	// issue @notice A live session for email, returning its id.
	issue := func(email string) string {
		t.Helper()
		uid := createUser(t, db, email)
		token, err := s.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.Lookup(ctx, db, token)
		if err != nil || p == nil {
			t.Fatalf("Lookup: %v, %v", p, err)
		}
		return p.SessionID
	}
	userOf := func(sessionID string) string {
		t.Helper()
		var uid string
		if _, err := db.QueryOne(pg.Scan(&uid),
			`select user_id from auth_sessions where id = ?`, sessionID); err != nil {
			t.Fatal(err)
		}
		return uid
	}

	t.Run("a live session records the factor", func(t *testing.T) {
		sid := issue("mfa-ok@example.test")
		if !mfaAt(t, db, sid).IsZero() {
			t.Fatal("mfa_at is set on a fresh session")
		}
		if err := s.RecordMFA(ctx, db, sid, userOf(sid)); err != nil {
			t.Fatalf("RecordMFA: %v", err)
		}
		if mfaAt(t, db, sid).IsZero() {
			t.Error("mfa_at is still null after RecordMFA")
		}
	})

	t.Run("the session is not rotated", func(t *testing.T) {
		// Rotation is Rotate's job. If RecordMFA rotated, every caller would silently invalidate
		// the cookie the client is still holding and the step-up would log the user out.
		uid := createUser(t, db, "mfa-norotate@example.test")
		token, err := s.Issue(ctx, db, uid, session.Meta{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.Lookup(ctx, db, token)
		if err != nil || p == nil {
			t.Fatalf("Lookup: %v, %v", p, err)
		}
		if err := s.RecordMFA(ctx, db, p.SessionID, uid); err != nil {
			t.Fatal(err)
		}
		after, err := s.Lookup(ctx, db, token)
		if err != nil {
			t.Fatal(err)
		}
		if after == nil {
			t.Fatal("the original token stopped resolving — RecordMFA rotated the credential")
		}
		if after.MFAAt.IsZero() {
			t.Error("the principal does not carry the recorded factor")
		}
	})

	t.Run("a revoked session cannot be elevated", func(t *testing.T) {
		sid := issue("mfa-revoked@example.test")
		if err := s.Revoke(ctx, db, sid); err != nil {
			t.Fatal(err)
		}
		err := s.RecordMFA(ctx, db, sid, userOf(sid))
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("RecordMFA on a revoked session: err = %v, want UNAUTHENTICATED", err)
		}
		// The assertion. Without it this test passes on an implementation that returns an error
		// and writes the row anyway, which would resurrect a revoked session as an elevated one.
		if !mfaAt(t, db, sid).IsZero() {
			t.Error("mfa_at was written on a revoked session")
		}
	})

	t.Run("an expired session cannot be elevated", func(t *testing.T) {
		sid := issue("mfa-expired@example.test")
		if _, err := db.Exec(
			`update auth_sessions set expires_at = now() - interval '1 second' where id = ?`, sid); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordMFA(ctx, db, sid, userOf(sid)); err == nil {
			t.Error("RecordMFA accepted an expired session")
		}
		if !mfaAt(t, db, sid).IsZero() {
			t.Error("mfa_at was written on an expired session")
		}
	})

	t.Run("one user cannot elevate another user's session", func(t *testing.T) {
		// The reason the statement matches on both ids. With only the session id, any caller
		// holding one would be stamping someone else's session as having passed a second factor.
		aSID := issue("mfa-a@example.test")
		bSID := issue("mfa-b@example.test")
		bUID := userOf(bSID)

		err := s.RecordMFA(ctx, db, aSID, bUID)
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeUnauthenticated {
			t.Errorf("cross-user RecordMFA: err = %v, want UNAUTHENTICATED", err)
		}
		if !mfaAt(t, db, aSID).IsZero() {
			t.Error("A's mfa_at was written by a call carrying B's user id")
		}
		if !mfaAt(t, db, bSID).IsZero() {
			t.Error("B's mfa_at was written by a call carrying A's session id")
		}
	})

	t.Run("the refusal wraps pg.ErrNoRows for zkauthn's classifier", func(t *testing.T) {
		// zkauthn's noRowsInvalid must keep distinguishing "session not live" from a driver
		// failure after this move: collapsing both into an invalid proof hides an outage, and
		// surfacing the difference is the oracle gotcha 63 exists to prevent.
		sid := issue("mfa-wrap@example.test")
		if err := s.Revoke(ctx, db, sid); err != nil {
			t.Fatal(err)
		}
		err := s.RecordMFA(ctx, db, sid, userOf(sid))
		if !errors.Is(err, pg.ErrNoRows) {
			t.Errorf("errors.Is(err, pg.ErrNoRows) = false for %v — zkauthn can no longer classify it", err)
		}
	})
}

// TestDBMFADirectiveReachable @notice The whole point of C4: a consumer with no Groth16 can now
// satisfy @auth(mfa: true).
//
// @dev Until RecordMFA existed, mfa_at had exactly one writer and it was inside zkauthn, so this
// sequence was unwritable by any consumer that did not deploy proving keys — the directive denied
// forever and the argument was documentation for a seam nothing could reach. The test runs the
// real directive over a principal resolved from a real session, so it fails if the column, the
// lookup, the Principal field or the directive's window drift apart.
//
// @param t the test handle
func TestDBMFADirectiveReachable(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	s, err := session.NewSessions(session.Options{Schema: testSchema})
	if err != nil {
		t.Fatal(err)
	}
	d := authz.Directive(authz.DirectiveOptions{MFAWindow: time.Minute})
	yes := true

	uid := createUser(t, db, "stepup@example.test")
	token, err := s.Issue(ctx, db, uid, session.Meta{})
	if err != nil {
		t.Fatal(err)
	}

	// principalCtx @notice The context a resolver would see, resolved the way the middleware does.
	principalCtx := func() context.Context {
		t.Helper()
		p, err := s.Lookup(ctx, db, token)
		if err != nil || p == nil {
			t.Fatalf("Lookup: %v, %v", p, err)
		}
		return authz.WithPrincipal(ctx, p)
	}

	ran, err := callDirective(t, d, principalCtx(), authz.LevelAuthenticated, nil, &yes)
	var ae *kalerr.Error
	if ran || !errors.As(err, &ae) || ae.Code != kalerr.CodeMFARequired {
		t.Fatalf("before RecordMFA: ran=%v err=%v, want MFA_REQUIRED", ran, err)
	}

	if err := s.RecordMFA(ctx, db, mustSessionID(t, s, ctx, db, token), uid); err != nil {
		t.Fatalf("RecordMFA: %v", err)
	}

	ran, err = callDirective(t, d, principalCtx(), authz.LevelAuthenticated, nil, &yes)
	if !ran || err != nil {
		t.Errorf("after RecordMFA: ran=%v err=%v, want the resolver to run", ran, err)
	}
}

// mustSessionID @notice The session id behind a wire token.
func mustSessionID(t *testing.T, s *session.Sessions, ctx context.Context, db *pg.DB, token string) string {
	t.Helper()
	p, err := s.Lookup(ctx, db, token)
	if err != nil || p == nil {
		t.Fatalf("Lookup: %v, %v", p, err)
	}
	return p.SessionID
}
