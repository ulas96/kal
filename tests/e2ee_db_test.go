package tests

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/e2ee"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// Every case in this file needs Postgres and is named TestDBE2EE* for that reason: CI greps
// `--- PASS: TestDB` out of the -v output and fails on `--- SKIP: TestDB`, so a database case named
// anything else is invisible to the gate that exists to catch exactly this
// (docs/e2ee-test-cases.md P-2).

// vaultPepper @notice The fixture pepper, fixed and never random.
//
// @dev Every salt case asserts on exact bytes. A random pepper makes them unreproducible, and the
// first flake gets them skipped. A case that needs a *second* pepper constructs a second Vaults
// explicitly and says so (P-4).
var vaultPepper = bytes.Repeat([]byte{0x2b}, 32)

// newVaultFixture @notice An authn fixture plus a Vaults against the same scratch schema.
func newVaultFixture(t *testing.T) (*authnFixture, *e2ee.Vaults) {
	t.Helper()
	f := newAuthnFixture(t)
	return f, f.vaultsWith(t, e2ee.Options{})
}

// vaultsWith @notice A second Vaults against the same schema, with opts's non-zero fields honoured.
//
// @dev The pepper and the schema default to the fixture's, so a case that is about MaxBlob or the
// floor does not have to restate them — and a case that is about the pepper sets it deliberately
// and is visible in the diff for doing so.
func (f *authnFixture) vaultsWith(t *testing.T, opts e2ee.Options) *e2ee.Vaults {
	t.Helper()
	if opts.Pepper == nil {
		opts.Pepper = vaultPepper
	}
	if opts.Schema == "" {
		opts.Schema = testSchema
	}
	v, err := e2ee.NewVaults(opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// vaultCtx @notice A context carrying the principal the vault methods read the user from.
//
// @dev Built directly rather than through the middleware: these tests are about what the vault
// statements do, and the middleware's own resolution is asserted in middleware_test.go.
func vaultCtx(userID, email string) context.Context {
	return authz.WithPrincipal(context.Background(),
		&authz.Principal{UserID: userID, SessionID: "vault-test", Email: email})
}

// validVault @notice A vault that passes every rule in check, for the cases whose subject is
// something else.
func validVault(key string) e2ee.Vault {
	return e2ee.Vault{
		WrappedKey:         []byte(key),
		RecoveryWrappedKey: []byte("the vault key under the recovery code"),
	}
}

// storedKey @notice A's wrapped key straight out of the table, for the tests that assert on the
// row rather than on a return value.
func storedKey(t *testing.T, db *pg.DB, userID string) []byte {
	t.Helper()
	var key []byte
	if _, err := db.QueryOne(pg.Scan(&key),
		`select wrapped_key from auth_e2ee_vaults where user_id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	return key
}

// storedVault @notice Every column of one vault row, for the cases that assert the row and not the
// projection.
type storedVault struct {
	KDF                string
	Salt               []byte
	Memory, Iterations uint32
	Parallelism        uint8
	WrappedKey         []byte
	RecoveryWrappedKey []byte
	WrappedFor         []byte
	KeyVersion         int
}

// vaultRow @notice The whole row, read directly.
//
// @dev Get's projection and the columns are two different things, and "nearly equivalent" is how
// they drift apart. A case about what was *stored* reads this.
func vaultRow(t *testing.T, db *pg.DB, userID string) storedVault {
	t.Helper()
	var v storedVault
	if _, err := db.QueryOne(pg.Scan(&v.KDF, &v.Salt, &v.Memory, &v.Iterations, &v.Parallelism,
		&v.WrappedKey, &v.RecoveryWrappedKey, &v.WrappedFor, &v.KeyVersion),
		`select kdf, salt, memory, iterations, parallelism, wrapped_key, recovery_wrapped_key,
		        wrapped_for, key_version
		   from auth_e2ee_vaults where user_id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	return v
}

// vaultRows @notice How many vault rows a user has, for the tests that assert a rejected write
// left nothing behind.
func vaultRows(t *testing.T, db *pg.DB, userID string) int {
	t.Helper()
	var n int
	if _, err := db.QueryOne(pg.Scan(&n),
		`select count(*) from auth_e2ee_vaults where user_id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	return n
}

// allVaultRows @notice Every vault row in the schema.
//
// @dev For the unauthenticated cases: there is no user id in that scenario, so counting per user
// would count nothing and pass.
func allVaultRows(t *testing.T, db *pg.DB) int {
	t.Helper()
	var n int
	if _, err := db.QueryOne(pg.Scan(&n), `select count(*) from auth_e2ee_vaults`); err != nil {
		t.Fatal(err)
	}
	return n
}

// loginAttempts @notice The recorded failure count for one address.
//
// @dev Keyed ('user', lower(email)) by authn's recordFailure — the same key resetBackoff deletes.
// Zero rows and a zero count are the same answer here, and both are what a pre-auth read must
// leave behind.
func loginAttempts(t *testing.T, db *pg.DB, email string) int {
	t.Helper()
	var n int
	if _, err := db.QueryOne(pg.Scan(&n),
		`select coalesce(sum(failures), 0)::int from auth_login_attempts
		  where scope = 'user' and key = ?`, strings.ToLower(email)); err != nil {
		t.Fatal(err)
	}
	return n
}

// schemaTables @notice Every base table in the scratch schema, from the catalogue.
//
// @dev Enumerated rather than listed, so a table added by a later migration is covered by
// construction rather than by somebody remembering to extend a literal.
func schemaTables(t *testing.T, db *pg.DB) []string {
	t.Helper()
	var rows []struct{ TableName string }
	if _, err := db.Query(&rows,
		`select table_name from information_schema.tables
		  where table_schema = ? and table_type = 'BASE TABLE' order by table_name`,
		testSchema); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.TableName)
	}
	return out
}

// tableCounts @notice Row counts for every table in the scratch schema.
func tableCounts(t *testing.T, db *pg.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, name := range schemaTables(t, db) {
		var n int
		if _, err := db.QueryOne(pg.Scan(&n), `select count(*) from ?`, pg.Ident(name)); err != nil {
			t.Fatal(err)
		}
		out[name] = n
	}
	return out
}

// directVaultColumns @notice A complete, valid set of column values for a raw insert.
func directVaultColumns(userID string) map[string]any {
	return map[string]any{
		"user_id":              userID,
		"kdf":                  e2ee.KDFArgon2id,
		"salt":                 bytes.Repeat([]byte{0x11}, 16),
		"memory":               65536,
		"iterations":           3,
		"parallelism":          1,
		"wrapped_key":          []byte("inserted without going through Put"),
		"recovery_wrapped_key": []byte("recovery"),
	}
}

// putVaultDirect @notice A raw insert into auth_e2ee_vaults, bypassing Put entirely.
//
// @dev The schema's own constraints are unreachable through Put — it hard-codes the parallelism
// literal and upserts on conflict — so a case about what the *database* refuses has to write the
// row itself. Returns the error rather than fataling: the constraint cases assert on it.
func putVaultDirect(db *pg.DB, cols map[string]any) error {
	names := make([]string, 0, len(cols))
	values := make([]any, 0, len(cols))
	placeholders := make([]string, 0, len(cols))
	for name, value := range cols {
		names = append(names, name)
		values = append(values, value)
		placeholders = append(placeholders, "?")
	}
	_, err := db.Exec(fmt.Sprintf(`insert into auth_e2ee_vaults (%s) values (%s)`,
		strings.Join(names, ", "), strings.Join(placeholders, ", ")), values...)
	return err
}

// expectedSalt @notice HMAC-SHA256(pepper, "kal.e2ee.salt|" + email)[:16], recomputed here.
//
// @dev This duplicates the implementation, which is acceptable here and only here: the domain
// string and the truncation are a wire contract a second client has to reproduce, and a test that
// called the package's own derivation would assert only that the function equals itself. Do not
// "simplify" this into a call to Params.
func expectedSalt(pepper []byte, email string) []byte {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte("kal.e2ee.salt|" + strings.ToLower(strings.TrimSpace(email))))
	return mac.Sum(nil)[:16]
}

// softDelete @notice Disables an account the way an operator would.
func softDelete(t *testing.T, db *pg.DB, userID string) {
	t.Helper()
	if _, err := db.Exec(`update auth_users set deleted_at = now() where id = ?`, userID); err != nil {
		t.Fatal(err)
	}
}

// passwordHash @notice The stored hash, for the cases that assert a credential did or did not move.
func passwordHash(t *testing.T, db *pg.DB, userID string) string {
	t.Helper()
	var hash string
	if _, err := db.QueryOne(pg.Scan(&hash),
		`select coalesce(password_hash, '') from auth_users where id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	return hash
}

// requireConflict @notice Asserts a *kalerr.Error carrying CodeConflict.
//
// @return the error, for the callers that go on to assert on its message; explicitly discarded at
// the sites that only need the code, because errcheck reads a dropped error return as a bug.
func requireConflict(t *testing.T, err error) *kalerr.Error {
	t.Helper()
	var ae *kalerr.Error
	if !errors.As(err, &ae) || ae.Code != kalerr.CodeConflict {
		t.Fatalf("error = %v, want CONFLICT", err)
	}
	return ae
}

// ---------------------------------------------------------------------------------------------
// §5 · the salt
// ---------------------------------------------------------------------------------------------

// TestDBE2EEEnumeration @notice Params answers identically for an unknown address and a known one
// with no vault, and its answer does not move between two calls.
//
// @dev Params is necessarily pre-auth — the client needs the salt before it can produce the auth
// secret — so it is an oracle unless every address gets an answer. The usual fix is a random
// decoy, and the usual fix is wrong: a decoy generated fresh per call changes between two calls
// and a real salt does not. Call twice, diff, enumerate. The stability assertion below is the
// whole point; a test that only checked "non-empty" passes against exactly that bug.
//
// Covers: E2EE-SLT-002, E2EE-SLT-004, E2EE-PRM-003
func TestDBE2EEEnumeration(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	unknown, err := v.Params(ctx, f.db, "nobody@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown.Salt) != 16 {
		t.Fatalf("salt is %d bytes, want 16", len(unknown.Salt))
	}
	again, err := v.Params(ctx, f.db, "nobody@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unknown.Salt, again.Salt) {
		t.Error("the decoy salt moved between two calls — that difference is the enumeration oracle")
	}

	f.createPasswordUser(t, "known@example.test", "the original password")
	known, err := v.Params(ctx, f.db, "known@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if known.KDF != unknown.KDF || known.Memory != unknown.Memory ||
		known.Iterations != unknown.Iterations || known.Parallelism != unknown.Parallelism {
		t.Errorf("an account with no vault answers differently from an unknown address:\n %+v\n %+v",
			known, unknown)
	}
	if bytes.Equal(known.Salt, unknown.Salt) {
		t.Error("two addresses derive the same salt")
	}

	// The address is normalised before it reaches the HMAC. Without that, one user typing their
	// address with a capital letter derives a different key and reports a corrupt vault.
	upper, err := v.Params(ctx, f.db, "  NOBODY@Example.Test  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(upper.Salt, unknown.Salt) {
		t.Error("the salt moves with the case or the whitespace of the address")
	}
}

// TestDBE2EEDecoyBecomesTheStoredSalt @notice The salt an address is given before it enrols is the
// salt it is given after.
//
// @dev The property the whole construction is for. Two code paths compute it — Params's no-row
// branch and Put's insert — and they happen to call the same function. If they ever diverge, the
// decoy becomes distinguishable from a real salt by enrolling and comparing, *and* every client
// that derived before enrolment derives a key that no longer opens its own vault. Both failures at
// once, neither with an error.
//
// Both reads go through Params deliberately, so the case exercises the no-row branch and the
// stored-row branch rather than calling one derivation twice.
//
// Covers: E2EE-SLT-001, E2EE-SLT-003
func TestDBE2EEDecoyBecomesTheStoredSalt(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "decoy@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	before, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Salt) != 16 {
		t.Fatalf("the decoy salt is %d bytes, want 16", len(before.Salt))
	}

	if err := v.Put(uctx, f.db, validVault("the enrolment wrapping")); err != nil {
		t.Fatal(err)
	}
	after, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Salt, after.Salt) {
		t.Fatalf("the salt changed across enrolment: %x then %x — every client that derived before "+
			"enrolling now holds a key that cannot open its own vault", before.Salt, after.Salt)
	}
	if len(vaultRow(t, f.db, id).Salt) != 16 {
		t.Errorf("the stored salt is %d bytes, want 16", len(vaultRow(t, f.db, id).Salt))
	}

	// The re-wrap path writes through a different clause; the salt must survive it too.
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("the re-wrap"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	third, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Salt, third.Salt) {
		t.Error("the salt moved on re-wrap")
	}

	// An address with no account at all is the third state, and it is 16 bytes as well.
	unknown, err := v.Params(ctx, f.db, "nobody-at-all@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown.Salt) != 16 {
		t.Errorf("an unknown address gets %d bytes, want 16", len(unknown.Salt))
	}
}

// TestDBE2EENormalisesBothPaths @notice The address is lowercased and trimmed on the write path as
// well as the read path.
//
// @dev Two normalisations, in two functions, that must agree forever. Drop either and one user
// typing their address with a capital letter derives a key that does not open the vault their
// other device wrote — mutation M-06, the failure with no symptom. Only the read path was covered
// before this case.
//
// The principal is built with the mixed-case string deliberately: a fixture that lowercased the
// address before it reached the principal would test nothing.
//
// Covers: E2EE-SLT-005
func TestDBE2EENormalisesBothPaths(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const stored = "MiXeD@Example.Test"
	const lower = "mixed@example.test"
	id := createUser(t, f.db, stored)

	before, err := v.Params(ctx, f.db, lower)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Put(vaultCtx(id, "  "+stored+"  "), f.db, validVault("wrapped on the odd path")); err != nil {
		t.Fatal(err)
	}
	if got := vaultRow(t, f.db, id).Salt; !bytes.Equal(got, before.Salt) {
		t.Errorf("Put stored salt %x, and the client derived from %x — the two paths normalise "+
			"differently and the vault this user just wrote can never be opened", got, before.Salt)
	}
	if got := vaultRow(t, f.db, id).Salt; !bytes.Equal(got, expectedSalt(vaultPepper, lower)) {
		t.Errorf("the stored salt is not HMAC(pepper, domain+lower(email)): %x", got)
	}

	// Trim and lowercase are separate operations, and one function might do only one.
	for _, variant := range []string{lower + " ", " " + lower, "MIXED@EXAMPLE.TEST", "  MiXeD@Example.Test  "} {
		got, err := v.Params(ctx, f.db, variant)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Salt, before.Salt) {
			t.Errorf("Params(%q) returned a different salt from Params(%q)", variant, lower)
		}
	}
}

// TestDBE2EESaltDependsOnPepper @notice The pepper is mixed in, the derivation is domain-separated,
// and the constructor keeps the caller's slice rather than a copy.
//
// @dev If the pepper is accepted and not actually mixed in, salt(email) is computable offline by
// anyone — the derivation is public and this file is public — and the decoy is distinguishable from
// a real salt without ever touching the server. The pepper is the only thing standing between a
// public derivation and an enumeration oracle.
//
// Both peppers are 32 bytes on purpose: two peppers of *different* lengths change the HMAC key
// block padding and would produce different output even under a construction that ignored the
// pepper's content.
//
// Covers: E2EE-SLT-006, E2EE-SLT-007, E2EE-CFG-004
func TestDBE2EESaltDependsOnPepper(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "pepper@example.test"

	other := f.vaultsWith(t, e2ee.Options{Pepper: bytes.Repeat([]byte{0x3c}, 32)})
	same := f.vaultsWith(t, e2ee.Options{Pepper: bytes.Repeat([]byte{0x2b}, 32)})

	mine, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := other.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mine.Salt, theirs.Salt) {
		t.Error("two deployments with different peppers derive the same salt — the pepper is not " +
			"reaching the HMAC, and salt(email) is computable by anyone")
	}
	twin, err := same.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mine.Salt, twin.Salt) {
		t.Error("the same pepper produced two different salts — the derivation is not deterministic")
	}

	// Domain separation. The pepper is deployment-wide, so any other use of it over the same input
	// would produce the same bytes for two different purposes.
	if !bytes.Equal(mine.Salt, expectedSalt(vaultPepper, addr)) {
		t.Errorf("salt = %x, want HMAC(pepper, \"kal.e2ee.salt|\"+email)[:16]", mine.Salt)
	}
	bare := hmac.New(sha256.New, vaultPepper)
	bare.Write([]byte(addr))
	if bytes.Equal(mine.Salt, bare.Sum(nil)[:16]) {
		t.Error("the salt is HMAC over the bare address — the domain prefix is gone")
	}

	// [UNSPECIFIED] §17.11: v.pepper = opts.Pepper with no copy. A consumer that reuses a scratch
	// buffer, or zeroes its config after construction, silently moves every salt derived
	// afterwards — and only for vaults written after the mutation, so the deployment splits into
	// two cohorts with no error anywhere. One bytes.Clone in NewVaults closes it.
	t.Run("the pepper is retained by reference", func(t *testing.T) {
		mutable := bytes.Repeat([]byte{0x5a}, 32)
		byRef := f.vaultsWith(t, e2ee.Options{Pepper: mutable})
		enrolled := f.createPasswordUser(t, "byref@example.test", "the original password")
		if err := byRef.Put(vaultCtx(enrolled, "byref@example.test"), f.db, validVault("wrapped")); err != nil {
			t.Fatal(err)
		}
		storedBefore, err := byRef.Params(ctx, f.db, "byref@example.test")
		if err != nil {
			t.Fatal(err)
		}
		decoyBefore, err := byRef.Params(ctx, f.db, "nobody-byref@example.test")
		if err != nil {
			t.Fatal(err)
		}

		// In place, not a reassignment: pepper = otherSlice proves nothing about aliasing.
		copy(mutable, bytes.Repeat([]byte{0x6b}, 32))

		decoyAfter, err := byRef.Params(ctx, f.db, "nobody-byref@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(decoyBefore.Salt, decoyAfter.Salt) {
			t.Error("mutating the caller's slice no longer moves the derived salt — NewVaults now " +
				"copies the pepper; that is the fix §17.11 asks for, so move the finding rather than " +
				"deleting this case")
		}
		storedAfter, err := byRef.Params(ctx, f.db, "byref@example.test")
		if err != nil {
			t.Fatal(err)
		}
		// The enrolled address reads its column either way, which is what makes the hazard a split
		// cohort rather than a total outage — and why nobody notices.
		if !bytes.Equal(storedBefore.Salt, storedAfter.Salt) {
			t.Error("an enrolled address's stored salt moved with the caller's buffer")
		}
	})
}

// TestDBE2EESaltSurvivesEmailChange @notice After an address change the account keeps the salt
// minted under the old one.
//
// @dev The stored salt is looked up by lower(u.email), so it follows the account, not the address
// — which is correct, and is exactly why this matters: the salt read back is now one that
// salt(newAddress) would never produce. A future "recompute if it looks wrong" repair job would
// destroy every affected vault.
//
// The fallthrough is asserted on the cost fields, not on the salt, for the reason
// TestDBE2EEParamsSoftDeleted gives: enrolment mints salt(email), so the stored salt of the old
// address and the decoy of the old address are the same sixteen bytes by construction
// (E2EE-SLT-003). A salt comparison there asserts nothing and cannot be made to — hence the
// non-default parameters below.
//
// Covers: E2EE-SLT-009
func TestDBE2EESaltSurvivesEmailChange(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const before, after = "before@example.test", "after@example.test"
	id := f.createPasswordUser(t, before, "the original password")

	if err := v.Put(vaultCtx(id, before), f.db, e2ee.Vault{
		WrappedKey:         []byte("wrapped under the old address"),
		RecoveryWrappedKey: []byte("the vault key under the recovery code"),
		Params:             e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}
	minted := vaultRow(t, f.db, id).Salt

	// A direct update: changing the address through a path that also rewrote the vault row would
	// hide the asymmetry this case is about.
	if _, err := f.db.Exec(`update auth_users set email = ? where id = ?`, after, id); err != nil {
		t.Fatal(err)
	}

	moved, err := v.Params(ctx, f.db, after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(moved.Salt, minted) {
		t.Errorf("Params(new address) = %x, want the stored %x", moved.Salt, minted)
	}
	if bytes.Equal(moved.Salt, expectedSalt(vaultPepper, after)) {
		t.Error("the salt was recomputed from the new address — every vault written under the old " +
			"one is now unopenable")
	}
	if moved.Memory != 131072 || moved.Iterations != 4 {
		t.Errorf("the new address read %d/%d, want the stored 131072/4 — it is not finding the row",
			moved.Memory, moved.Iterations)
	}

	// The other half of the asymmetry: the old address no longer resolves to the account and falls
	// through to the decoy. Its salt is unchanged by that — it equals `minted`, because that is the
	// value enrolment stored — so the cost fields are what shows the fallthrough happened.
	orphan, err := v.Params(ctx, f.db, before)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orphan.Salt, expectedSalt(vaultPepper, before)) {
		t.Errorf("the old address returned %x, want its decoy", orphan.Salt)
	}
	if !bytes.Equal(orphan.Salt, minted) {
		t.Errorf("the old address's decoy %x is not the salt enrolment minted for it (%x) — "+
			"E2EE-SLT-003 says the two are one value, and a vault re-derived here would not open",
			orphan.Salt, minted)
	}
	if orphan.Memory != 65536 || orphan.Iterations != 3 {
		t.Errorf("the old address read the stored parameters (%d/%d) — it still resolves to the row, "+
			"and an address the account no longer has is an oracle for one it used to",
			orphan.Memory, orphan.Iterations)
	}
}

// TestDBE2EEClientSaltIgnored @notice A salt supplied by the client is never stored.
//
// @dev A client-chosen salt breaks decoy indistinguishability outright: enrol with a salt of
// 0x00 × 16 and every subsequent Params for that address is trivially distinguishable from a decoy.
// The parameter list in putVaultSQL never binds vault.Params.Salt, and the doc comment says so — a
// case is what keeps it that way.
//
// The column is read, not the projection: Get reads the same column, so the two are nearly
// equivalent, and "nearly" is how a projection and a column drift apart.
//
// Covers: E2EE-SLT-010
func TestDBE2EEClientSaltIgnored(t *testing.T) {
	f, v := newVaultFixture(t)

	for _, tc := range []struct {
		name  string
		email string
		salt  []byte
	}{
		{"attacker-chosen, right length", "chosen@example.test", bytes.Repeat([]byte{0xff}, 16)},
		// The field is ignored, not validated: a wrong-length salt is neither stored nor rejected,
		// and the case records which.
		{"the wrong length entirely", "shortsalt@example.test", []byte{1, 2, 3, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := f.createPasswordUser(t, tc.email, "the original password")
			err := v.Put(vaultCtx(id, tc.email), f.db, e2ee.Vault{
				WrappedKey:         []byte("wrapped"),
				RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{
					KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Salt: tc.salt,
				},
			})
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			got := vaultRow(t, f.db, id).Salt
			if bytes.Equal(got, tc.salt) {
				t.Fatalf("the client's own bytes are in the salt column: %x", got)
			}
			if !bytes.Equal(got, expectedSalt(vaultPepper, tc.email)) {
				t.Errorf("salt column = %x, want kal's derived salt", got)
			}
		})
	}
}

// TestDBE2EESaltNeverRotates @notice The stored salt survives a re-wrap.
//
// @dev A salt recomputed or re-minted on write moves the moment anything about the account moves,
// and every wrapped key in the deployment becomes garbage — silently, with a working login and an
// unopenable vault. Rotating it is a re-wrap flow, not something a second Put does by accident.
//
// Covers: E2EE-SLT-008
func TestDBE2EESaltNeverRotates(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	id := f.createPasswordUser(t, "salt@example.test", "the original password")
	uctx := vaultCtx(id, "salt@example.test")

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("first"), RecoveryWrappedKey: []byte("recovery"),
	}); err != nil {
		t.Fatal(err)
	}
	first, err := v.Params(ctx, f.db, "salt@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("second"), RecoveryWrappedKey: []byte("recovery"),
		Params:     e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
		KeyVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	second, err := v.Params(ctx, f.db, "salt@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Salt, second.Salt) {
		t.Error("the salt changed on re-wrap — every existing wrapped key in the deployment is now garbage")
	}
	// The cost parameters, unlike the salt, must move: that is what makes lifting a user off a
	// weak KDF a re-wrap on their next login rather than a migration.
	if second.Memory != 131072 || second.Iterations != 4 {
		t.Errorf("re-wrap did not store the new parameters: %+v", second)
	}
}

// ---------------------------------------------------------------------------------------------
// §6 · the pre-auth parameter query
// ---------------------------------------------------------------------------------------------

// TestDBE2EEParamsIsPreAuth @notice Params needs no principal, and writes nothing at all.
//
// @dev Adding authz.Require here looks like tightening and is a deadlock: the client needs the
// salt *before* it can produce the auth secret it would authenticate with, and at registration the
// account does not exist yet. The other three methods do require one, which is what makes this a
// deliberate opening rather than authentication that was never wired.
//
// A Params that lazily materialised a row would give an unauthenticated caller row creation and
// make "a row exists" true for every address anyone ever asked about, destroying the distinction
// the decoy exists to hide.
//
// Covers: E2EE-PRM-001, E2EE-PRM-011
func TestDBE2EEParamsIsPreAuth(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	if _, err := v.Params(ctx, f.db, "bare@example.test"); err != nil {
		t.Fatalf("Params on a bare context: %v", err)
	}
	// The context the middleware installs for a request with no cookie: a jar and request
	// attribution, and no principal. authz.WithPrincipal(ctx, nil) is a no-op, so this is the only
	// way to build the anonymous shape a resolver actually sees.
	f.request(t, "", "192.0.2.60", func(reqCtx context.Context) error {
		if _, err := v.Params(reqCtx, f.db, "anon@example.test"); err != nil {
			t.Errorf("Params on an anonymous request context: %v", err)
		}
		if _, err := v.Get(reqCtx, f.db); err == nil {
			t.Error("Get succeeded on the anonymous context — see TestDBE2EEVaultRequiresAuth")
		}
		return nil
	})

	before := tableCounts(t, f.db)
	for i := 0; i < 20; i++ {
		if _, err := v.Params(ctx, f.db, fmt.Sprintf("unknown-%d@example.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	for name, count := range tableCounts(t, f.db) {
		if before[name] != count {
			t.Errorf("%s went from %d rows to %d across twenty pre-auth reads", name, before[name], count)
		}
	}

	// The negative variant: without it, this case passes against a database nothing is writing to.
	id := f.createPasswordUser(t, "writes@example.test", "the original password")
	if err := v.Put(vaultCtx(id, "writes@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if after := tableCounts(t, f.db)["auth_e2ee_vaults"]; after != before["auth_e2ee_vaults"]+1 {
		t.Errorf("auth_e2ee_vaults = %d rows after a Put, want %d — the counter is not counting",
			after, before["auth_e2ee_vaults"]+1)
	}
}

// TestDBE2EEParamsUnknownAddress @notice An address with no account gets a complete answer, never
// an error and never a zero field.
//
// @dev Any distinguishable response is an account-enumeration oracle on a pre-auth endpoint. An
// error, an empty salt, a zero KDF string or a different field set are all the same finding — the
// response body is the oracle, not the error.
//
// Covers: E2EE-PRM-002
func TestDBE2EEParamsUnknownAddress(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	got, err := v.Params(ctx, f.db, "definitely-not-here@example.test")
	if err != nil {
		t.Fatalf("an unknown address produced an error: %v", err)
	}
	if got.KDF != e2ee.KDFArgon2id {
		t.Errorf("KDF = %q, want argon2id", got.KDF)
	}
	if len(got.Salt) != 16 {
		t.Errorf("salt is %d bytes, want 16", len(got.Salt))
	}
	if got.Memory != 65536 || got.Iterations != 3 || got.Parallelism != 1 {
		t.Errorf("cost = %d/%d/%d, want 65536/3/1", got.Memory, got.Iterations, got.Parallelism)
	}

	// A full answer that does not match a real account's is still an oracle.
	f.createPasswordUser(t, "registered@example.test", "the original password")
	known, err := v.Params(ctx, f.db, "registered@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if known.KDF != got.KDF || known.Memory != got.Memory ||
		known.Iterations != got.Iterations || known.Parallelism != got.Parallelism {
		t.Errorf("registered-but-unenrolled answers %+v, unknown answers %+v", known, got)
	}
}

// TestDBE2EEParamsStoredBeatsConfig @notice An enrolled user's parameters come from their row, and
// keep coming from it after the deployment raises its defaults.
//
// @dev Gotcha 67, and the quietest catastrophe in the module. Read the parameters from
// configuration at derive time and the first Default change makes every existing vault unopenable —
// with a working login, a valid session, and no error anywhere in the system. Raising the cost
// after an audit is the recommended thing to do and has to be safe.
//
// Covers: E2EE-PRM-004, E2EE-PRM-005
func TestDBE2EEParamsStoredBeatsConfig(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	// Values that differ from the default in *both* fields: enrolling at the default would make the
	// assertion vacuous.
	loud := f.createPasswordUser(t, "loud@example.test", "the original password")
	if err := v.Put(vaultCtx(loud, "loud@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := v.Params(ctx, f.db, "loud@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Memory != 131072 || stored.Iterations != 4 {
		t.Errorf("an enrolled user's parameters = %d/%d, want the stored 131072/4",
			stored.Memory, stored.Iterations)
	}
	// The same instance must still answer the default for an address with no row, or the case
	// cannot tell "reads the row" from "ignores configuration entirely".
	unenrolled, err := v.Params(ctx, f.db, "unenrolled@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if unenrolled.Memory != 65536 || unenrolled.Iterations != 3 {
		t.Errorf("an unenrolled address = %d/%d, want the configured 65536/3",
			unenrolled.Memory, unenrolled.Iterations)
	}

	// The actual failure scenario: an operator raises the cost after an audit, and a user enrolled
	// under the old configuration reads through the new one.
	quiet := f.createPasswordUser(t, "quiet@example.test", "the original password")
	if err := v.Put(vaultCtx(quiet, "quiet@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	raised := f.vaultsWith(t, e2ee.Options{Default: e2ee.Params{Memory: 262144, Iterations: 6}})

	through, err := raised.Params(ctx, f.db, "quiet@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if through.Memory != 65536 || through.Iterations != 3 {
		t.Errorf("after the default was raised, an enrolled user reads %d/%d — every vault written "+
			"under the old configuration is now unopenable", through.Memory, through.Iterations)
	}
	// Without this arm a Vaults that ignored Default entirely would pass: the raised configuration
	// has to be live for the row's win to mean anything.
	fresh, err := raised.Params(ctx, f.db, "brand-new@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Memory != 262144 || fresh.Iterations != 6 {
		t.Errorf("the raised default is not in effect for a new address: %d/%d", fresh.Memory, fresh.Iterations)
	}
}

// TestDBE2EEParamsNoBackoff @notice Asking for a salt does not feed the login backoff.
//
// @dev Gotcha 69, and the one denial of service in this module an unauthenticated attacker can
// drive at no cost. Rate-limiting a pre-auth endpoint through the login counter lets anyone lock
// any account out by repeatedly asking for its salt. Nothing in the code does this today; the case
// exists because it is the obvious "fix" a reviewer proposes the first time someone points at an
// unauthenticated endpoint. Rate-limit at the edge instead.
//
// Covers: E2EE-PRM-006
func TestDBE2EEParamsNoBackoff(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "backoff@example.test"
	const password = "the original password"
	f.createPasswordUser(t, addr, password)

	// Comfortably above the threshold: three consecutive failures already open the window
	// (TestDBLoginBackoff pins the curve).
	for i := 0; i < 50; i++ {
		if _, err := v.Params(ctx, f.db, addr); err != nil {
			t.Fatal(err)
		}
	}
	if n := loginAttempts(t, f.db, addr); n != 0 {
		t.Errorf("fifty pre-auth reads left %d backoff rows — anyone can lock this account out by "+
			"asking for its salt", n)
	}

	var principal *authz.Principal
	f.request(t, "", "192.0.2.70", func(reqCtx context.Context) error {
		var err error
		principal, err = f.accounts.Login(reqCtx, f.db, addr, password)
		return err
	})
	if f.lastErr != nil || principal == nil {
		t.Fatalf("the account could not log in after fifty Params calls: %v", f.lastErr)
	}

	// The negative variant: without it the case passes against a backoff that counts nothing at
	// all, which asserts nothing about Params.
	t.Run("real failures still count", func(t *testing.T) {
		var last error
		for i := 0; i < 3; i++ {
			f.request(t, "", "192.0.2.71", func(reqCtx context.Context) error {
				_, err := f.accounts.Login(reqCtx, f.db, addr, "not the password")
				return err
			})
			last = f.lastErr
		}
		if n := loginAttempts(t, f.db, addr); n == 0 {
			t.Error("three failed logins recorded nothing — the counter this case is about is dead")
		}
		var ae *kalerr.Error
		if !errors.As(last, &ae) || ae.Code != kalerr.CodeRateLimited {
			t.Errorf("the third failure = %v, want RATE_LIMITED", last)
		}
	})
}

// TestDBE2EEParamsSoftDeleted @notice A disabled account reads as an address with no account.
//
// @dev paramsByEmailSQL gates u.deleted_at is null deliberately. Drop the gate and a deleted user's
// stored parameters keep answering, which tells an attacker the account existed.
//
// The assertion is on the cost fields, not the salt: enrolment gives a user a salt equal to their
// own decoy (E2EE-SLT-003), so the salt cannot distinguish a stored answer from a fallback one.
// That is why this case enrols with parameters that differ from the default.
//
// Covers: E2EE-PRM-007
func TestDBE2EEParamsSoftDeleted(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "disabled@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}
	// Before the delete the same call must return the stored values, or this passes against a
	// statement that never finds anything.
	live, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if live.Memory != 131072 || live.Iterations != 4 {
		t.Fatalf("before the soft delete: %+v, want the stored 131072/4", live)
	}

	softDelete(t, f.db, id)

	after, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatalf("a soft-deleted address errored: %v", err)
	}
	if after.Memory != 65536 || after.Iterations != 3 {
		t.Errorf("a soft-deleted account still answers with its stored parameters (%d/%d) — the row "+
			"is now an oracle for accounts that existed", after.Memory, after.Iterations)
	}
	if !bytes.Equal(after.Salt, expectedSalt(vaultPepper, addr)) {
		t.Errorf("the decoy salt for a disabled account is not the ordinary decoy: %x", after.Salt)
	}
}

// TestDBE2EEParamsUnverified @notice Verification state does not change the answer.
//
// @dev A verification-gated Params is an oracle for "this address registered and has not confirmed
// yet", which is more than the login path gives out.
//
// Covers: E2EE-PRM-008
func TestDBE2EEParamsUnverified(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	verified := f.createPasswordUser(t, "verified@example.test", "the original password")
	// Inserted directly: createPasswordUser sets email_verified = true, which is the whole
	// distinction this case rests on.
	var unverified string
	if _, err := f.db.QueryOne(pg.Scan(&unverified),
		`insert into auth_users (email, password_hash, email_verified)
		 values ('unverified@example.test', 'x', false) returning id`); err != nil {
		t.Fatal(err)
	}

	params := e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4}
	for id, addr := range map[string]string{
		verified: "verified@example.test", unverified: "unverified@example.test",
	} {
		if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: params,
		}); err != nil {
			t.Fatal(err)
		}
	}

	a, err := v.Params(ctx, f.db, "verified@example.test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.Params(ctx, f.db, "unverified@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if a.KDF != b.KDF || a.Memory != b.Memory || a.Iterations != b.Iterations ||
		a.Parallelism != b.Parallelism {
		t.Errorf("verification state changes the answer:\n verified   %+v\n unverified %+v", a, b)
	}
	// Both must be reading their rows: two addresses that both fell through to the default would
	// also be identical, and would assert nothing.
	if a.Memory != 131072 || b.Memory != 131072 {
		t.Errorf("one of the two fell through to the default: %d and %d", a.Memory, b.Memory)
	}
}

// TestDBE2EEParamsParallelism @notice Every answer carries Parallelism 1, including for a client
// that asked for something else.
//
// @dev Gotcha 66. Argon2's p changes the output, so a client that reads parallelism from this
// response and gets 0, or 2, derives a different key than the device that wrote the vault, and the
// second device reports a corrupt vault. Three mechanisms pin the value — withDefaults, the SQL
// literal and the check constraint — and none of them is the one a client reads. The client reads
// this response.
//
// Covers: E2EE-PRM-009
func TestDBE2EEParamsParallelism(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	decoy, err := v.Params(ctx, f.db, "nobody-p@example.test")
	if err != nil {
		t.Fatal(err)
	}
	plain := f.createPasswordUser(t, "plain-p@example.test", "the original password")
	if err := v.Put(vaultCtx(plain, "plain-p@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	enrolled, err := v.Params(ctx, f.db, "plain-p@example.test")
	if err != nil {
		t.Fatal(err)
	}
	// The arm that matters: a client that *asks* for 4 is still told 1. Without it the case only
	// proves the default is 1.
	greedy := f.createPasswordUser(t, "greedy-p@example.test", "the original password")
	if err := v.Put(vaultCtx(greedy, "greedy-p@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Parallelism: 4},
	}); err != nil {
		t.Fatal(err)
	}
	asked, err := v.Params(ctx, f.db, "greedy-p@example.test")
	if err != nil {
		t.Fatal(err)
	}

	for name, got := range map[string]e2ee.Params{"decoy": decoy, "enrolled": enrolled, "asked for 4": asked} {
		if got.Parallelism != 1 {
			t.Errorf("%s: parallelism = %d, want 1", name, got.Parallelism)
		}
	}
}

// TestDBE2EEParamsCaseCollision @notice Two live addresses differing only in case cannot exist, and
// the pre-auth query is single-row for that reason.
//
// @dev [UNSPECIFIED] §17.7. paramsByEmailSQL matches on lower(u.email) and runs through
// QueryOneContext, so two matching rows would be a driver error surfaced from an unauthenticated
// endpoint. Whether auth_users permits such a pair is a 0001_core.sql question this case answers
// rather than assumes: the unique index is partial over live rows, so the live pair is refused and
// a soft-deleted twin is permitted — which is the arm that proves the gate in the statement is
// what keeps it single-row.
//
// Covers: E2EE-PRM-010
func TestDBE2EEParamsCaseCollision(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	first := createUser(t, f.db, "User@example.test")
	if _, err := f.db.Exec(
		`insert into auth_users (email, email_verified) values ('user@example.test', true)`); err == nil {
		t.Fatal("two live accounts differing only in case were accepted — Params would then be a " +
			"driver error on an unauthenticated path (§17.7)")
	}

	// The single-row case still works, so a constraint discovered mid-case does not leave the
	// group untested.
	single, err := v.Params(ctx, f.db, "user@example.test")
	if err != nil {
		t.Fatalf("Params on the surviving row: %v", err)
	}
	if len(single.Salt) != 16 {
		t.Errorf("salt is %d bytes, want 16", len(single.Salt))
	}

	// The partial index covers live rows only, so a soft-deleted twin is permitted — and the
	// statement's own deleted_at gate is what keeps the answer single-row.
	softDelete(t, f.db, first)
	if _, err := f.db.Exec(
		`insert into auth_users (email, email_verified) values ('user@example.test', true)`); err != nil {
		t.Fatalf("a live address whose twin is soft-deleted was refused: %v", err)
	}
	if _, err := v.Params(ctx, f.db, "user@example.test"); err != nil {
		t.Errorf("Params with one live and one deleted match: %v", err)
	}
}

// TestDBE2EEParamsConcurrent @notice Fifty simultaneous reads of one address return fifty identical
// answers.
//
// @dev Any per-call state — a cache with a race, a lazily seeded value — reintroduces the moving
// decoy that E2EE-SLT-002 rules out, but only under load, where no sequential test looks. The
// barrier is the shape: comparing responses after the fact without one serialises the calls and
// tests nothing.
//
// Covers: E2EE-PRM-012
func TestDBE2EEParamsConcurrent(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	id := f.createPasswordUser(t, "concurrent@example.test", "the original password")
	if err := v.Put(vaultCtx(id, "concurrent@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}

	// Both paths: the decoy comes from the HMAC, the enrolled answer comes from the row.
	for _, addr := range []string{"nobody-concurrent@example.test", "concurrent@example.test"} {
		const attempts = 50
		var wg sync.WaitGroup
		start := make(chan struct{})
		got := make([]e2ee.Params, attempts)
		errs := make([]error, attempts)
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				got[i], errs[i] = v.Params(ctx, f.db, addr)
			}(i)
		}
		close(start)
		wg.Wait()

		for i := range got {
			if errs[i] != nil {
				t.Fatalf("%s: attempt %d: %v", addr, i, errs[i])
			}
			if !bytes.Equal(got[i].Salt, got[0].Salt) || got[i].Memory != got[0].Memory ||
				got[i].Iterations != got[0].Iterations || got[i].KDF != got[0].KDF {
				t.Fatalf("%s: attempt %d answered %+v, attempt 0 answered %+v", addr, i, got[i], got[0])
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// §7 · Get, Put, Discard
// ---------------------------------------------------------------------------------------------

// TestDBE2EEVaultRequiresAuth @notice None of the three authenticated methods does anything for a
// caller with no principal.
//
// @dev authz.Require is the only thing between an unauthenticated caller and a wrapped key, and
// nothing tested it for any of the three before this case. The anonymous context is not
// hypothetical: the middleware never returns 401 — anonymous is an ordinary state the graph
// branches on — so a request with no cookie reaches a resolver with a jar, request attribution and
// no principal, which is exactly what is built here. There is no exported way to construct an
// "anonymous principal" value: authz.WithPrincipal(ctx, nil) returns the context unchanged, so the
// absence *is* the shape.
//
// Each method asserts the damage it would do, not the error: a Get that returns a vault beside its
// error hands the key to the caller that ignores errors, which is the caller this control exists
// for.
//
// Covers: E2EE-VLT-001, E2EE-VLT-002, E2EE-VLT-003, E2EE-VLT-004
func TestDBE2EEVaultRequiresAuth(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "owner@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	owner := vaultCtx(id, addr)
	key := []byte("the owner's wrapped vault key")
	if err := v.Put(owner, f.db, e2ee.Vault{
		WrappedKey: key, RecoveryWrappedKey: []byte("recovery"),
	}); err != nil {
		t.Fatal(err)
	}

	deny := func(t *testing.T, name string, ctx context.Context) {
		t.Helper()
		got, err := v.Get(ctx, f.db)
		requireErrorCode(t, err, kalerr.CodeUnauthenticated)
		if got != nil {
			t.Errorf("%s: Get returned a vault beside its error: %+v", name, got)
		}

		before := allVaultRows(t, f.db)
		err = v.Put(ctx, f.db, validVault("written by nobody"))
		requireErrorCode(t, err, kalerr.CodeUnauthenticated)
		// The whole table, not one user's rows: there is no user id in this scenario, so a
		// per-user count would count nothing and pass.
		if after := allVaultRows(t, f.db); after != before {
			t.Errorf("%s: an unauthenticated Put moved the table from %d rows to %d", name, before, after)
		}

		err = v.Discard(ctx, f.db)
		requireErrorCode(t, err, kalerr.CodeUnauthenticated)
		// Bytes, not the count: a delete-and-reinsert would preserve the count.
		if stored := storedKey(t, f.db, id); !bytes.Equal(stored, key) {
			t.Errorf("%s: the owner's key is now %q after an unauthenticated Discard", name, stored)
		}
	}

	t.Run("a bare context", func(t *testing.T) {
		deny(t, "bare context", context.Background())
	})

	t.Run("the context the middleware installs for a cookie-less request", func(t *testing.T) {
		f.request(t, "", "192.0.2.80", func(reqCtx context.Context) error {
			if _, ok := authz.From(reqCtx); ok {
				t.Fatal("the middleware installed a principal for a request with no cookie")
			}
			deny(t, "anonymous request context", reqCtx)
			return nil
		})
	})

	// The negative variant: without it a set of methods that always error would pass every arm
	// above, and that implementation breaks every consumer.
	t.Run("the owner still reaches their own vault", func(t *testing.T) {
		got, err := v.Get(owner, f.db)
		if err != nil || got == nil {
			t.Fatalf("Get as the owner = %v, %v", got, err)
		}
		if !bytes.Equal(got.WrappedKey, key) {
			t.Errorf("the owner read %q, want %q", got.WrappedKey, key)
		}
		if err := v.Put(owner, f.db, e2ee.Vault{
			WrappedKey: []byte("a re-wrap"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
		}); err != nil {
			t.Errorf("Put as the owner: %v", err)
		}
	})
}

// TestDBE2EEVaultScope @notice One user's vault operations cannot reach another's row.
//
// @dev Asserted by A's row still being present and unchanged after B has done everything B can
// do. A Discard that reported success while deleting the wrong row would pass any version of this
// test that only checked B's return values.
//
// Covers: E2EE-VLT-007, E2EE-VLT-008, E2EE-VLT-009
func TestDBE2EEVaultScope(t *testing.T) {
	f, v := newVaultFixture(t)
	aID := f.createPasswordUser(t, "a@example.test", "the original password")
	bID := f.createPasswordUser(t, "b@example.test", "the original password")

	aKey := []byte("A's wrapped vault key")
	if err := v.Put(vaultCtx(aID, "a@example.test"), f.db, e2ee.Vault{
		WrappedKey: aKey, RecoveryWrappedKey: []byte("A's recovery wrapping"),
	}); err != nil {
		t.Fatal(err)
	}

	bCtx := vaultCtx(bID, "b@example.test")
	got, err := v.Get(bCtx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("B read a vault it never wrote: %+v", got)
	}
	// B's Discard correctly returns nil for a user with no row. A case written to expect an error
	// here would be "fixed" by making Discard fail on a missing row, which is the wrong contract.
	if err := v.Discard(bCtx, f.db); err != nil {
		t.Fatal(err)
	}
	bKey := []byte("B's wrapped vault key")
	if err := v.Put(bCtx, f.db, e2ee.Vault{
		WrappedKey: bKey, RecoveryWrappedKey: []byte("B's recovery"),
	}); err != nil {
		t.Fatal(err)
	}

	if stored := storedKey(t, f.db, aID); !bytes.Equal(stored, aKey) {
		t.Errorf("A's wrapped key is now %q, want %q", stored, aKey)
	}
	// And B's own write landed: a Put that silently did nothing would satisfy the assertion above.
	if stored := storedKey(t, f.db, bID); !bytes.Equal(stored, bKey) {
		t.Errorf("B's wrapped key is %q, want %q", stored, bKey)
	}
}

// TestDBE2EEGetAbsence @notice A user who never enrolled reads as nil, not as an error and not as
// an empty vault.
//
// @dev Returning an error here pushes every consumer into errors.Is(err, pg.ErrNoRows) at the
// resolver, which leaks a driver type through the API and becomes a 500 on the enrolment path
// every new user takes. A zero-valued non-nil *Vault is worse than either: the caller then hands a
// client an empty wrapped key.
//
// Covers: E2EE-VLT-005
func TestDBE2EEGetAbsence(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "never-enrolled@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	got, err := v.Get(uctx, f.db)
	if err != nil {
		t.Fatalf("Get before enrolment: %v", err)
	}
	if got != nil {
		t.Fatalf("Get returned %+v for a user with no row", got)
	}

	if err := v.Put(uctx, f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	got, err = v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get after enrolment = %+v, %v", got, err)
	}
}

// TestDBE2EEGetRoundTripsParams @notice Get projects the same five parameters Params does.
//
// @dev Two statements project the same five columns in the same order and both scan positionally
// with no struct tags, so field order in the SQL is the entire contract. Swap two columns in one
// and the client derives with the wrong memory cost.
//
// The comparison is against Params(email), not against the struct that was passed to Put: Salt is
// ignored on write and Parallelism is forced, so that comparison fails for the right reasons and
// gets "fixed" by weakening it.
//
// Covers: E2EE-VLT-006
func TestDBE2EEGetRoundTripsParams(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "roundtrip@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	// Values distinguishable from each other and from the defaults: Memory 3 / Iterations 3 would
	// hide exactly the swap this case exists to catch.
	if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}

	pre, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(vaultCtx(id, addr), f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Params.KDF != pre.KDF || !bytes.Equal(got.Params.Salt, pre.Salt) ||
		got.Params.Memory != pre.Memory || got.Params.Iterations != pre.Iterations ||
		got.Params.Parallelism != pre.Parallelism {
		t.Errorf("Get projects %+v, Params projects %+v — one of the two statements has its columns "+
			"in a different order, and the client derives with the wrong cost", got.Params, pre)
	}
	if got.Params.Memory != 131072 || got.Params.Iterations != 4 {
		t.Errorf("Get lost the stored cost: %+v", got.Params)
	}
}

// TestDBE2EEDiscardDeletes @notice Discard removes the caller's row, and doing it twice is not an
// error.
//
// @dev Written next to TestDBE2EEVaultScope on purpose: that case proves B's Discard did not hit
// A, which a Discard that is a complete no-op also satisfies. A no-op leaves the user who asked to
// destroy their vault believing it is gone. Neither case should be deleted without the other.
//
// Covers: E2EE-VLT-010
func TestDBE2EEDiscardDeletes(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "discard@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if n := vaultRows(t, f.db, id); n != 1 {
		t.Fatalf("%d rows after Put, want 1", n)
	}

	if err := v.Discard(uctx, f.db); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if n := vaultRows(t, f.db, id); n != 0 {
		t.Errorf("%d rows survived the owner's own Discard", n)
	}
	got, err := v.Get(uctx, f.db)
	if err != nil || got != nil {
		t.Errorf("Get after Discard = %+v, %v", got, err)
	}
	// Idempotence is the documented behaviour; a case that expected an error here would pin the
	// wrong contract.
	if err := v.Discard(uctx, f.db); err != nil {
		t.Errorf("a second Discard = %v, want nil", err)
	}
}

// TestDBE2EEPutStaleVersion @notice A sequential write at a version that has moved on is a
// conflict, and changes nothing.
//
// @dev Only the concurrent race was tested before this case. The sequential one is what every real
// client hits: two tabs, one stale read, a re-wrap submitted from the older one. If the CAS is
// absent the loser silently overwrites a key the winner has already shown its user, and that
// user's next login fails against a vault key they were told was theirs.
//
// The bytes are asserted, not just the error: a CAS that returns CONFLICT *after* writing is
// exactly the bug, and it is reachable — the conflict is derived from pg.ErrNoRows on a returning
// clause, so an implementation that split the statement would produce it.
//
// Covers: E2EE-VLT-011
func TestDBE2EEPutStaleVersion(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "stale-version@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("the enrolment wrapping")); err != nil {
		t.Fatal(err)
	}
	second := []byte("the second wrapping")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: second, RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}

	err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey:         []byte("the wrapping from the stale tab"),
		RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
	})
	_ = requireConflict(t, err)
	if stored := storedKey(t, f.db, id); !bytes.Equal(stored, second) {
		t.Errorf("the table holds %q after a rejected write, want %q", stored, second)
	}

	// The negative variant: a Put at the correct version must succeed, or a Put that always
	// conflicts passes.
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey:         []byte("the correctly versioned wrapping"),
		RecoveryWrappedKey: []byte("recovery"), KeyVersion: 2,
	}); err != nil {
		t.Errorf("a correctly versioned Put was rejected: %v", err)
	}
}

// TestDBE2EEKeyVersionIncrements @notice Each successful write moves the version by exactly one.
//
// @dev The version is the client's only handle on the CAS. If it jumps, or does not move, a
// correct client is locked out of ever writing again — every subsequent Put conflicts with
// CONFLICT as the only diagnostic, and the user cannot re-wrap after a password change.
//
// The version is read through Get: Put scans `returning key_version` into a local and discards it
// (§17.5), so a client cannot chain two writes without a Get in between.
//
// Covers: E2EE-VLT-012
func TestDBE2EEKeyVersionIncrements(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "versions@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("the first wrapping")); err != nil {
		t.Fatal(err)
	}
	// The column defaults to 1 and the update adds 1, so an off-by-one here would make every
	// client's first re-wrap conflict.
	got, err := v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.KeyVersion != 1 {
		t.Fatalf("the first Put produced version %d, want 1", got.KeyVersion)
	}

	for want := 2; want <= 4; want++ {
		if err := v.Put(uctx, f.db, e2ee.Vault{
			WrappedKey:         []byte(fmt.Sprintf("wrapping %d", want)),
			RecoveryWrappedKey: []byte("recovery"),
			KeyVersion:         got.KeyVersion,
		}); err != nil {
			t.Fatalf("re-wrap at version %d: %v", got.KeyVersion, err)
		}
		got, err = v.Get(uctx, f.db)
		if err != nil || got == nil {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if got.KeyVersion != want {
			t.Fatalf("version = %d, want %d", got.KeyVersion, want)
		}
	}
}

// TestDBE2EEPutConcurrency @notice Two devices re-wrapping at the same version: exactly one wins,
// and the table holds the winner's key.
//
// @dev A real race, not a theoretical one — a password change on a laptop and a phone within the
// same minute is the ordinary case. A read-then-write implementation passes every sequential test
// and fails this one, and its failure mode is that a user is shown a key that was silently
// overwritten a moment later.
//
// Covers: E2EE-VLT-013, E2EE-VLT-014
func TestDBE2EEPutConcurrency(t *testing.T) {
	f, v := newVaultFixture(t)
	id := f.createPasswordUser(t, "race@example.test", "the original password")
	uctx := vaultCtx(id, "race@example.test")

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("the enrolment wrapping"), RecoveryWrappedKey: []byte("recovery"),
	}); err != nil {
		t.Fatal(err)
	}
	before, err := v.Get(uctx, f.db)
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, attempts)
	keys := make([][]byte, attempts)
	for i := 0; i < attempts; i++ {
		// Distinguishable blobs: the same value in every goroutine makes the stored-key assertion
		// below vacuous.
		keys[i] = []byte(fmt.Sprintf("the re-wrap from device %d", i))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = v.Put(uctx, f.db, e2ee.Vault{
				WrappedKey: keys[i], RecoveryWrappedKey: []byte("recovery"),
				KeyVersion: before.KeyVersion,
			})
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, err := range errs {
		if err == nil {
			if winner >= 0 {
				t.Errorf("attempts %d and %d were both told they succeeded", winner, i)
			}
			winner = i
			continue
		}
		var ae *kalerr.Error
		if !errors.As(err, &ae) || ae.Code != kalerr.CodeConflict {
			t.Errorf("attempt %d: error = %v, want CONFLICT", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("every concurrent re-wrap lost — the user's vault now holds a key no device has")
	}
	stored := storedKey(t, f.db, id)
	if !bytes.Equal(stored, keys[winner]) {
		t.Errorf("the table holds %q, but attempt %d is the one that was told it won", stored, winner)
	}
	// Every loser's blob must be absent: one winner and somebody else's bytes is a system that
	// told a user their key is safe and stored another's.
	for i, key := range keys {
		if i != winner && bytes.Equal(stored, key) {
			t.Errorf("the stored key is loser %d's", i)
		}
	}
}

// TestDBE2EEPutFirstWriteIgnoresVersion @notice [UNSPECIFIED] The CAS does not apply to the first
// write.
//
// @dev §17.4. `where auth_e2ee_vaults.key_version = ?` lives inside the on-conflict clause, so on
// the insert path the parameter is bound and never consulted — a client that sends a stale
// non-zero version at enrolment gets a success it should not have, and the mismatch surfaces on
// its *next* write. Vault.KeyVersion's doc says "Zero means no row yet", which is the half of the
// contract that is true.
//
// Pinned as it behaves, deliberately: written as a test that expected a rejection it would fail
// and be deleted rather than becoming the finding it is.
//
// Covers: E2EE-VLT-015
func TestDBE2EEPutFirstWriteIgnoresVersion(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "firstwrite@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 57,
	}); err != nil {
		t.Fatalf("a first Put carrying a nonsense version was rejected: %v — if the insert path now "+
			"consults KeyVersion, §17.4 has been closed and this case records the new behaviour", err)
	}
	got, err := v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.KeyVersion != 1 {
		t.Errorf("version after the first Put = %d, want 1", got.KeyVersion)
	}

	// The same version against an existing row does conflict, which is what pins where the
	// predicate applies and where it does not.
	err = v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("second"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 57,
	})
	_ = requireConflict(t, err)
}

// TestDBE2EEPutDeletedUser @notice [UNSPECIFIED] An absent or disabled account is reported as a
// conflict.
//
// @dev §17.6. The insert's `where u.id = ? and u.deleted_at is null` yields zero rows, which
// becomes pg.ErrNoRows, which becomes "the vault changed since it was read; re-read it and try
// again". A client that follows that instruction re-reads, finds nothing, retries, and loops. The
// condition is not a conflict — it is a deleted account.
//
// The message is asserted as well as the code, because the message is the finding.
//
// Covers: E2EE-VLT-016
func TestDBE2EEPutDeletedUser(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "putdeleted@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	// The same write must succeed before the delete, so the case isolates deleted_at as the cause
	// rather than the version.
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("re-wrapped"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
	}); err != nil {
		t.Fatalf("a correctly versioned Put before the soft delete: %v", err)
	}

	softDelete(t, f.db, id)

	ae := requireConflict(t, v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("after the delete"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 2,
	}))
	const message = "the vault changed since it was read; re-read it and try again"
	if ae.Message != message {
		t.Errorf("message = %q, want %q — if the wording changed, §17.6 moves with it", ae.Message, message)
	}

	// A principal naming a user that does not exist takes the same branch. It is reachable from a
	// hand-built principal, and it reports the same wrong thing.
	ghost := vaultCtx("11111111-1111-1111-1111-111111111111", "ghost@example.test")
	_ = requireConflict(t, v.Put(ghost, f.db, validVault("from nowhere")))
}

// TestDBE2EEGetSoftDeleted @notice [UNSPECIFIED] A disabled account can still read its wrapped key.
//
// @dev §17.8. paramsByEmailSQL gates deleted_at and vaultByUserSQL does not, so a soft-deleted
// account whose session has not been revoked still reads its vault while its address reads as
// unknown pre-auth. Whether that is right depends on what soft delete means in the deployment, and
// the code says nothing either way — which is the finding.
//
// Asserting Params in the same case is what makes the asymmetry visible rather than a bare
// observation. Session revocation does not make this unreachable: it is a property of the
// statement, and the statement is what is asserted.
//
// Covers: E2EE-VLT-017
func TestDBE2EEGetSoftDeleted(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "getdeleted@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	key := []byte("the disabled account's key")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: key, RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}
	softDelete(t, f.db, id)

	got, err := v.Get(uctx, f.db)
	if err != nil {
		t.Fatalf("Get for a soft-deleted user: %v", err)
	}
	if got == nil || !bytes.Equal(got.WrappedKey, key) {
		t.Errorf("Get = %+v — if the vault statement grew a deleted_at gate, §17.8 has been settled "+
			"and this case records the decision", got)
	}

	pre, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if pre.Memory != 65536 || pre.Iterations != 3 {
		t.Errorf("Params for the same disabled account returned the stored %d/%d — the asymmetry "+
			"this case records has moved", pre.Memory, pre.Iterations)
	}
}

// TestDBE2EEEmptyEmailSalt @notice [UNSPECIFIED] A principal with no Email derives one salt shared
// by every such user.
//
// @dev §17.9. Put takes the address from p.Email, so a principal built by a code path that does
// not populate it — a JWT-only session, or a resolver constructing one by hand — produces
// HMAC(pepper, "kal.e2ee.salt|"), identical for every such user and one that no Params(email) call
// can ever return. The vault is written and can never be opened, because the client asked for a
// different salt.
//
// Covers: E2EE-VLT-018
func TestDBE2EEEmptyEmailSalt(t *testing.T) {
	f, v := newVaultFixture(t)
	first := f.createPasswordUser(t, "noemail-a@example.test", "the original password")
	second := f.createPasswordUser(t, "noemail-b@example.test", "the original password")

	for _, id := range []string{first, second} {
		if err := v.Put(vaultCtx(id, ""), f.db, validVault("wrapped by a principal with no address")); err != nil {
			t.Fatal(err)
		}
	}
	a, b := vaultRow(t, f.db, first).Salt, vaultRow(t, f.db, second).Salt
	if !bytes.Equal(a, b) {
		t.Errorf("two empty-email principals derived %x and %x — if Put now rejects or resolves the "+
			"address, §17.9 has been settled and this case records how", a, b)
	}
	if !bytes.Equal(a, expectedSalt(vaultPepper, "")) {
		t.Errorf("the shared salt is %x, want HMAC(pepper, domain) with an empty address", a)
	}

	// With addresses the same two users get different salts, which is what makes the collision a
	// finding rather than a coincidence about these two rows.
	third := f.createPasswordUser(t, "withemail-a@example.test", "the original password")
	fourth := f.createPasswordUser(t, "withemail-b@example.test", "the original password")
	if err := v.Put(vaultCtx(third, "withemail-a@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(vaultCtx(fourth, "withemail-b@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(vaultRow(t, f.db, third).Salt, vaultRow(t, f.db, fourth).Salt) {
		t.Error("two addressed principals share a salt")
	}
}

// ---------------------------------------------------------------------------------------------
// §4 · the configuration, against a live schema
// ---------------------------------------------------------------------------------------------

// TestDBE2EEMaxBlob @notice The blob ceiling binds at its exact boundary, and the zero Options is
// bounded.
//
// @dev A `< 0` guard instead of `<= 0` leaves MaxBlob: 0 meaning "no limit", and the zero Options
// is the one every consumer starts from — an authenticated caller then has a free storage bucket,
// replicated and backed up at the operator's expense (gotcha 77). The negative arm is what catches
// it: testing only MaxBlob: 0 cannot distinguish the two guards.
//
// Covers: E2EE-CFG-006, E2EE-CFG-007
func TestDBE2EEMaxBlob(t *testing.T) {
	f := newAuthnFixture(t)

	t.Run("zero and negative both mean 8192", func(t *testing.T) {
		for name, configured := range map[string]int{"zero": 0, "negative": -1} {
			v := f.vaultsWith(t, e2ee.Options{MaxBlob: configured})
			at := f.createPasswordUser(t, name+"-at@example.test", "the original password")
			if err := v.Put(vaultCtx(at, name+"-at@example.test"), f.db, e2ee.Vault{
				WrappedKey: bytes.Repeat([]byte{0x41}, 8192), RecoveryWrappedKey: []byte("recovery"),
			}); err != nil {
				t.Errorf("MaxBlob %d: 8192 bytes rejected: %v", configured, err)
			}
			over := f.createPasswordUser(t, name+"-over@example.test", "the original password")
			err := v.Put(vaultCtx(over, name+"-over@example.test"), f.db, e2ee.Vault{
				WrappedKey: bytes.Repeat([]byte{0x41}, 8193), RecoveryWrappedKey: []byte("recovery"),
			})
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
			if n := vaultRows(t, f.db, over); n != 0 {
				t.Errorf("MaxBlob %d: the write was rejected and %d row(s) landed anyway", configured, n)
			}
		}
	})

	// A boundary test at the default value tells you nothing about whether the field is read.
	t.Run("a custom ceiling binds at its own boundary", func(t *testing.T) {
		v := f.vaultsWith(t, e2ee.Options{MaxBlob: 64})
		// Both blobs are checked against the same ceiling in one condition; a case that only moved
		// WrappedKey would not notice if that stopped being true.
		for _, field := range []string{"wrapped", "recovery"} {
			for _, size := range []int{63, 64, 65} {
				email := fmt.Sprintf("blob-%s-%d@example.test", field, size)
				id := f.createPasswordUser(t, email, "the original password")
				blob := bytes.Repeat([]byte{0x42}, size)
				vault := e2ee.Vault{WrappedKey: blob, RecoveryWrappedKey: []byte("recovery")}
				if field == "recovery" {
					vault = e2ee.Vault{WrappedKey: []byte("wrapped"), RecoveryWrappedKey: blob}
				}
				err := v.Put(vaultCtx(id, email), f.db, vault)
				if size <= 64 {
					if err != nil {
						t.Errorf("%s at %d bytes was rejected under MaxBlob 64: %v", field, size, err)
					}
					continue
				}
				requireErrorCode(t, err, kalerr.CodeInvalidInput)
				if n := vaultRows(t, f.db, id); n != 0 {
					t.Errorf("%s at %d bytes: %d row(s) landed anyway", field, size, n)
				}
			}
		}
	})
}

// TestDBE2EEDefaultsFillZeroFields @notice Options.Default replaces only the fields the caller left
// zero.
//
// @dev A withDefaults that replaced the whole struct would silently discard a deployment's
// deliberate cost choice, and the first symptom is a phone that takes eleven seconds to log in.
//
// Covers: E2EE-CFG-008
func TestDBE2EEDefaultsFillZeroFields(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		configured e2ee.Params
		want       e2ee.Params
	}{
		// The fully-zero case pins the documented default rather than merely "something non-zero".
		"nothing set":      {e2ee.Params{}, e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Parallelism: 1}},
		"memory only":      {e2ee.Params{Memory: 262144}, e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 262144, Iterations: 3, Parallelism: 1}},
		"iterations only":  {e2ee.Params{Iterations: 6}, e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 6, Parallelism: 1}},
		"kdf only":         {e2ee.Params{KDF: e2ee.KDFPBKDF2}, e2ee.Params{KDF: e2ee.KDFPBKDF2, Memory: 65536, Iterations: 3, Parallelism: 1}},
		"parallelism only": {e2ee.Params{Parallelism: 4}, e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Parallelism: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			v := f.vaultsWith(t, e2ee.Options{Default: tc.configured})
			got, err := v.Params(ctx, f.db, "defaults-"+strings.ReplaceAll(name, " ", "-")+"@example.test")
			if err != nil {
				t.Fatal(err)
			}
			if got.KDF != tc.want.KDF || got.Memory != tc.want.Memory ||
				got.Iterations != tc.want.Iterations || got.Parallelism != tc.want.Parallelism {
				t.Errorf("Default %+v produced %+v, want %+v", tc.configured, got, tc.want)
			}
		})
	}
}

// TestDBE2EEFloorBinds @notice A raised floor is consulted, and two of Floor's five fields are not.
//
// @dev A floor that is configured and not consulted reads as a control in code review and is not
// one. It is also the field a deployment reaches for after an incident, so a dead one is
// discovered at the worst moment.
//
// The second half is [UNSPECIFIED] §17.2 and §17.3: check compares Memory and Iterations only, so
// a deployment that sets Floor{KDF: KDFArgon2id} believing it has banned PBKDF2 has banned
// nothing — and PBKDF2 is GPU-cheap (gotcha 75). Parallelism on both Default and Floor is
// overwritten by withDefaults before anything could read it. Pinned as it behaves; written as a
// test of a *working* KDF floor it would fail and be deleted.
//
// Covers: E2EE-CFG-009, E2EE-CFG-010
func TestDBE2EEFloorBinds(t *testing.T) {
	f := newAuthnFixture(t)
	defaultFloor := f.vaultsWith(t, e2ee.Options{})
	raised := f.vaultsWith(t, e2ee.Options{Floor: e2ee.Params{Memory: 131072}})

	ordinary := e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3}

	accepted := f.createPasswordUser(t, "floor-ok@example.test", "the original password")
	if err := defaultFloor.Put(vaultCtx(accepted, "floor-ok@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: ordinary,
	}); err != nil {
		t.Fatalf("65536/3 under the default floor: %v", err)
	}

	rejected := f.createPasswordUser(t, "floor-raised@example.test", "the original password")
	err := raised.Put(vaultCtx(rejected, "floor-raised@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: ordinary,
	})
	requireErrorCode(t, err, kalerr.CodeInvalidInput)
	if n := vaultRows(t, f.db, rejected); n != 0 {
		t.Errorf("the raised floor rejected the write and %d row(s) landed anyway", n)
	}
	// Without this arm a floor that rejects everything would pass.
	if err := raised.Put(vaultCtx(rejected, "floor-raised@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 3},
	}); err != nil {
		t.Errorf("a write at exactly the raised floor was rejected: %v", err)
	}

	t.Run("Floor.KDF is never compared", func(t *testing.T) {
		banned := f.vaultsWith(t, e2ee.Options{Floor: e2ee.Params{KDF: e2ee.KDFArgon2id}})
		id := f.createPasswordUser(t, "floor-kdf@example.test", "the original password")
		err := banned.Put(vaultCtx(id, "floor-kdf@example.test"), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFPBKDF2, Memory: 65536, Iterations: 3},
		})
		if err != nil {
			t.Fatalf("pbkdf2 under Floor{KDF: argon2id} was rejected: %v — if the floor now compares "+
				"the KDF, §17.2 has been closed and this case records it", err)
		}
		if got := vaultRow(t, f.db, id).KDF; got != e2ee.KDFPBKDF2 {
			t.Errorf("stored kdf = %q, want pbkdf2", got)
		}
		// The allowlist still fires, so the case does not read as "the KDF is unchecked".
		other := f.createPasswordUser(t, "floor-kdf-unknown@example.test", "the original password")
		err = banned.Put(vaultCtx(other, "floor-kdf-unknown@example.test"), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: "scrypt", Memory: 65536, Iterations: 3},
		})
		requireErrorCode(t, err, kalerr.CodeInvalidInput)
	})
}

// TestDBE2EESchemaRenders @notice The accepted schema qualifiers produce statements that actually
// run.
//
// @dev A regex that is right and a types.AppendIdent that is wrong is still broken, and only
// executing the rendered statements shows it. The unqualified form is not an oddity: the harness
// applies the migrations through search_path, which is the same mechanism a consumer isolating
// kal's tables uses.
//
// Covers: E2EE-CFG-005
func TestDBE2EESchemaRenders(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()

	for name, schema := range map[string]string{"qualified": testSchema, "unqualified": ""} {
		t.Run(name, func(t *testing.T) {
			v, err := e2ee.NewVaults(e2ee.Options{Pepper: vaultPepper, Schema: schema})
			if err != nil {
				t.Fatal(err)
			}
			email := name + "-schema@example.test"
			id := f.createPasswordUser(t, email, "the original password")
			uctx := vaultCtx(id, email)

			if _, err := v.Params(ctx, f.db, email); err != nil {
				t.Fatalf("Params: %v", err)
			}
			if err := v.Put(uctx, f.db, validVault("wrapped")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if got, err := v.Get(uctx, f.db); err != nil || got == nil {
				t.Fatalf("Get = %+v, %v", got, err)
			}
			if err := v.Discard(uctx, f.db); err != nil {
				t.Fatalf("Discard: %v", err)
			}
		})
	}
}

// TestDBE2EEVaultsAreIndependent @notice Two services built from one Options do not share mutable
// state.
//
// @dev Options is taken by value, but Pepper is a slice and the statements are rendered per call.
// A future field that is a map or a pointer would alias silently across every consumer, and the
// symptom would be one service answering with another's configuration.
//
// Covers: E2EE-CFG-011
func TestDBE2EEVaultsAreIndependent(t *testing.T) {
	f := newAuthnFixture(t)
	ctx := context.Background()
	opts := e2ee.Options{Pepper: vaultPepper, Schema: testSchema}

	a, err := e2ee.NewVaults(opts)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := opts
	elsewhere.Schema = "somewhere_else"
	b, err := e2ee.NewVaults(elsewhere)
	if err != nil {
		t.Fatal(err)
	}

	// Behaviour, not pointers: A still targets the schema it was built for after B was built for
	// another one.
	before, err := a.Params(ctx, f.db, "independent@example.test")
	if err != nil {
		t.Fatalf("A after B was constructed: %v", err)
	}
	if _, err := b.Params(ctx, f.db, "independent@example.test"); err == nil {
		t.Error("B answered against a schema that does not exist — the qualifier is not being rendered")
	}
	if _, err := a.Params(ctx, f.db, "independent@example.test"); err != nil {
		t.Errorf("A stopped working after B failed: %v", err)
	}

	// They share a pepper by design, so the case must not read as "these should differ".
	c, err := e2ee.NewVaults(opts)
	if err != nil {
		t.Fatal(err)
	}
	twin, err := c.Params(ctx, f.db, "independent@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Salt, twin.Salt) {
		t.Error("two services from one Options derive different salts")
	}
}

// ---------------------------------------------------------------------------------------------
// §8 · check, the policy that cannot live in the schema
// ---------------------------------------------------------------------------------------------

// TestDBE2EEParamsFloor @notice A Put below Options.Floor is rejected and writes no row.
//
// @dev This moves Memory and Iterations together, so it cannot tell which comparison fired — a
// floor that checks only one of the two passes it. TestDBE2EEFloorFieldsAreIndependent is the case
// that separates them, and this one is kept because it is the shape a consumer's own test takes.
//
// Covers: E2EE-POL-010
func TestDBE2EEParamsFloor(t *testing.T) {
	f, v := newVaultFixture(t)
	id := f.createPasswordUser(t, "floor@example.test", "the original password")

	err := v.Put(vaultCtx(id, "floor@example.test"), f.db, e2ee.Vault{
		WrappedKey:         []byte("wrapped under a KDF nobody should be using"),
		RecoveryWrappedKey: []byte("recovery"),
		Params:             e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 1024, Iterations: 1},
	})
	var ae *kalerr.Error
	if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
		t.Fatalf("error = %v, want INVALID_INPUT", err)
	}
	if n := vaultRows(t, f.db, id); n != 0 {
		t.Errorf("the write was rejected and %d row(s) landed anyway", n)
	}
}

// TestDBE2EEFloorFieldsAreIndependent @notice Memory and Iterations are compared separately.
//
// @dev The two are one `||` condition. Drop the second operand and a client can enrol at 64 MiB
// with a single pass, which is a real cost reduction against the adversary this module exists for,
// and nothing in the response differs.
//
// Iterations: 1 rather than 0 on purpose — withDefaults fills a zero to 3 before the comparison
// runs, so the zero *passes* the floor and would assert nothing.
//
// Covers: E2EE-POL-010, E2EE-POL-011
func TestDBE2EEFloorFieldsAreIndependent(t *testing.T) {
	f, v := newVaultFixture(t)

	for name, params := range map[string]e2ee.Params{
		"memory below the floor, iterations fine": {KDF: e2ee.KDFArgon2id, Memory: 1024, Iterations: 3},
		"iterations below the floor, memory fine": {KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 1},
	} {
		t.Run(name, func(t *testing.T) {
			email := strings.ReplaceAll(name, " ", "-") + "@example.test"
			id := f.createPasswordUser(t, email, "the original password")
			err := v.Put(vaultCtx(id, email), f.db, e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: params,
			})
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
			if n := vaultRows(t, f.db, id); n != 0 {
				t.Errorf("rejected, and %d row(s) landed anyway", n)
			}
		})
	}

	// The baseline both arms are measured against.
	id := f.createPasswordUser(t, "floor-baseline@example.test", "the original password")
	if err := v.Put(vaultCtx(id, "floor-baseline@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3},
	}); err != nil {
		t.Errorf("65536/3 was rejected: %v", err)
	}
}

// TestDBE2EEPutRejects @notice The policy that cannot live in the schema, and the row it must not
// leave behind.
//
// @dev Every rejection here is otherwise valid: check returns on the first failure, so a case that
// broke two rules at once would be asserting the wrong one. Each subtest takes its own address
// (P-6), and each asserts the row as well as the error (P-8).
//
// Covers: E2EE-POL-001, E2EE-POL-002, E2EE-POL-003, E2EE-POL-005, E2EE-POL-007
func TestDBE2EEPutRejects(t *testing.T) {
	f, v := newVaultFixture(t)

	tests := []struct {
		name  string
		email string
		vault e2ee.Vault
	}{
		{
			// Without a recovery wrapping a forgotten password is unrecoverable data loss, and the
			// resulting support queue cannot be answered by anyone, including the operator.
			name: "no recovery wrapping", email: "norecovery@example.test",
			vault: e2ee.Vault{WrappedKey: []byte("wrapped")},
		},
		{
			// The empty slice is the arm that distinguishes a nil check from a length check.
			name: "an empty recovery wrapping", email: "emptyrecovery@example.test",
			vault: e2ee.Vault{WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte{}},
		},
		{
			// An authenticated caller with an unbounded bytea column has a free storage bucket.
			name: "blob over MaxBlob", email: "toobig@example.test",
			vault: e2ee.Vault{
				WrappedKey:         bytes.Repeat([]byte{0x41}, 8193),
				RecoveryWrappedKey: []byte("recovery"),
			},
		},
		{
			// The second operand of the same condition. Nothing tested it before, so a refactor that
			// split the check and dropped one arm would leave half the storage bucket open — and the
			// recovery blob is the half with no size expectation in any client.
			name: "recovery wrapping over MaxBlob", email: "recoverytoobig@example.test",
			vault: e2ee.Vault{
				WrappedKey:         bytes.Repeat([]byte{0x41}, 64),
				RecoveryWrappedKey: bytes.Repeat([]byte{0x41}, 8193),
			},
		},
		{
			name: "no wrapped key at all", email: "empty@example.test",
			vault: e2ee.Vault{RecoveryWrappedKey: []byte("recovery")},
		},
		{
			name: "an empty wrapped key", email: "emptykey@example.test",
			vault: e2ee.Vault{WrappedKey: []byte{}, RecoveryWrappedKey: []byte("recovery")},
		},
		{
			name: "an unknown client KDF", email: "unknownkdf@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: "scrypt", Memory: 65536, Iterations: 3},
			},
		},
		{
			name: "another unknown KDF", email: "bcrypt@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: "bcrypt", Memory: 65536, Iterations: 3},
			},
		},
		{
			// The near misses are what a real client sends, and they are what distinguishes an exact
			// comparison from a fuzzy one.
			name: "the right KDF in the wrong case", email: "wrongcase@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: "Argon2id", Memory: 65536, Iterations: 3},
			},
		},
		{
			name: "a neighbouring KDF", email: "argon2i@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: "argon2i", Memory: 65536, Iterations: 3},
			},
		},
		{
			name: "the right KDF with a trailing space", email: "trailing@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: "argon2id ", Memory: 65536, Iterations: 3},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := f.createPasswordUser(t, tc.email, "the original password")
			err := v.Put(vaultCtx(id, tc.email), f.db, tc.vault)
			var ae *kalerr.Error
			if !errors.As(err, &ae) || ae.Code != kalerr.CodeInvalidInput {
				t.Fatalf("error = %v, want INVALID_INPUT", err)
			}
			if n := vaultRows(t, f.db, id); n != 0 {
				t.Errorf("the write was rejected and %d row(s) landed anyway", n)
			}
		})
	}

	// The negative variants, without which a check that rejects everything passes every row above —
	// and that implementation stops anyone enrolling at all.
	accepted := []struct {
		name  string
		email string
		vault e2ee.Vault
	}{
		{
			// The rule is emptiness, not a minimum size: a later `len < 32` guard would break a
			// legitimate short blob, and only this arm would see it.
			name: "a one-byte wrapped key", email: "onebyte@example.test",
			vault: e2ee.Vault{WrappedKey: []byte{0x01}, RecoveryWrappedKey: []byte{0x02}},
		},
		{
			name: "argon2id", email: "argon2id-ok@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3},
			},
		},
		{
			name: "pbkdf2", email: "pbkdf2-ok@example.test",
			vault: e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
				Params: e2ee.Params{KDF: e2ee.KDFPBKDF2, Memory: 65536, Iterations: 3},
			},
		},
	}
	for _, tc := range accepted {
		t.Run("accepted: "+tc.name, func(t *testing.T) {
			id := f.createPasswordUser(t, tc.email, "the original password")
			if err := v.Put(vaultCtx(id, tc.email), f.db, tc.vault); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if n := vaultRows(t, f.db, id); n != 1 {
				t.Errorf("%d rows after an accepted Put, want 1", n)
			}
		})
	}
}

// TestDBE2EEAllowNoRecovery @notice The opt-out works, and the vault it produces reports its empty
// recovery wrapping honestly.
//
// @dev A dead opt-out means a deployment that deliberately chose no recovery cannot enrol anyone,
// and the field reads as configuration that does nothing. It is also the arm that proves the
// default rejection is a *rule* and not an unrelated failure — which is why the same vault is
// pushed through the default configuration in the same case.
//
// What the opt-out costs a user who then forgets their password is asserted end to end by
// TestDBE2EERecoveryPathEndToEnd.
//
// Covers: E2EE-POL-006
func TestDBE2EEAllowNoRecovery(t *testing.T) {
	f, strict := newVaultFixture(t)
	lenient := f.vaultsWith(t, e2ee.Options{AllowNoRecovery: true})

	const addr = "optout@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := lenient.Put(uctx, f.db, e2ee.Vault{WrappedKey: []byte("wrapped")}); err != nil {
		t.Fatalf("AllowNoRecovery did not allow a vault with no recovery wrapping: %v", err)
	}
	if n := vaultRows(t, f.db, id); n != 1 {
		t.Errorf("%d rows after an accepted Put, want 1", n)
	}
	got, err := lenient.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if len(got.RecoveryWrappedKey) != 0 {
		t.Errorf("a recovery wrapping appeared from somewhere: %q", got.RecoveryWrappedKey)
	}

	// The same write through the default configuration is refused, or the opt-out proves nothing.
	other := f.createPasswordUser(t, "optout-control@example.test", "the original password")
	requireErrorCode(t,
		strict.Put(vaultCtx(other, "optout-control@example.test"), f.db,
			e2ee.Vault{WrappedKey: []byte("wrapped")}),
		kalerr.CodeInvalidInput)
	if n := vaultRows(t, f.db, other); n != 0 {
		t.Errorf("the default configuration rejected the write and %d row(s) landed anyway", n)
	}
}

// TestDBE2EEBoundariesAccepted @notice The ceiling and the floor are inclusive, and the bytes come
// back intact.
//
// @dev A `>=` where a `>` belongs rejects a blob a correct client produced, and the user cannot
// enrol at all — with INVALID_INPUT and no explanation of which input. At the other end, a `<=`
// where a `<` belongs rejects OWASP's own recommendation, which is the value a careful client
// sends.
//
// Covers: E2EE-POL-004, E2EE-POL-012
func TestDBE2EEBoundariesAccepted(t *testing.T) {
	f, v := newVaultFixture(t)

	t.Run("exactly at the blob ceiling", func(t *testing.T) {
		const addr = "ceiling@example.test"
		id := f.createPasswordUser(t, addr, "the original password")
		blob := bytes.Repeat([]byte{0x43}, 8192)
		if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
			WrappedKey: blob, RecoveryWrappedKey: []byte("recovery"),
		}); err != nil {
			t.Fatalf("8192 bytes rejected: %v", err)
		}
		// Read back, not merely accepted: a bytea round trip through a positional scan is exactly
		// where a truncation would hide.
		got, err := v.Get(vaultCtx(id, addr), f.db)
		if err != nil || got == nil {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if !bytes.Equal(got.WrappedKey, blob) {
			t.Errorf("the blob came back %d bytes, want %d", len(got.WrappedKey), len(blob))
		}

		over := f.createPasswordUser(t, "over-ceiling@example.test", "the original password")
		err = v.Put(vaultCtx(over, "over-ceiling@example.test"), f.db, e2ee.Vault{
			WrappedKey: bytes.Repeat([]byte{0x43}, 8193), RecoveryWrappedKey: []byte("recovery"),
		})
		requireErrorCode(t, err, kalerr.CodeInvalidInput)
	})

	t.Run("exactly at the parameter floor", func(t *testing.T) {
		const addr = "at-floor@example.test"
		id := f.createPasswordUser(t, addr, "the original password")
		if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 19456, Iterations: 2},
		}); err != nil {
			t.Fatalf("OWASP's own recommendation was rejected: %v", err)
		}
		if row := vaultRow(t, f.db, id); row.Memory != 19456 || row.Iterations != 2 {
			t.Errorf("stored %d/%d, want 19456/2", row.Memory, row.Iterations)
		}

		// One unit below each, so the case is about the boundary and not about the floor existing.
		for name, params := range map[string]e2ee.Params{
			"one KiB below":       {KDF: e2ee.KDFArgon2id, Memory: 19455, Iterations: 2},
			"one iteration below": {KDF: e2ee.KDFArgon2id, Memory: 19456, Iterations: 1},
		} {
			email := strings.ReplaceAll(name, " ", "-") + "@example.test"
			below := f.createPasswordUser(t, email, "the original password")
			err := v.Put(vaultCtx(below, email), f.db, e2ee.Vault{
				WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: params,
			})
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
		}
	})
}

// TestDBE2EEEmptyKDFIsFilled @notice A zero Params is filled from the defaults, not rejected.
//
// @dev withDefaults runs before the allowlist comparison, so "" becomes "argon2id" and passes.
// That is intentional — a client that omits parameters gets the deployment's defaults — but it
// means the allowlist never sees an empty string, and a reader of check alone would conclude
// otherwise.
//
// Covers: E2EE-POL-009
func TestDBE2EEEmptyKDFIsFilled(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "emptykdf@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Params: e2ee.Params{},
	}); err != nil {
		t.Fatalf("a zero Params was rejected: %v", err)
	}
	row := vaultRow(t, f.db, id)
	if row.KDF != e2ee.KDFArgon2id || row.Memory != 65536 || row.Iterations != 3 {
		t.Errorf("stored %q/%d/%d, want argon2id/65536/3", row.KDF, row.Memory, row.Iterations)
	}

	// A non-empty unknown KDF must still be rejected, so the case does not read as "the KDF is
	// never checked".
	other := f.createPasswordUser(t, "emptykdf-control@example.test", "the original password")
	err := v.Put(vaultCtx(other, "emptykdf-control@example.test"), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
		Params: e2ee.Params{KDF: "scrypt", Memory: 65536, Iterations: 3},
	})
	requireErrorCode(t, err, kalerr.CodeInvalidInput)
}

// TestDBE2EEPBKDF2RoundTrip @notice A PBKDF2 vault can be written, read, and lifted to Argon2id by
// a re-wrap.
//
// @dev Gotcha 75: WebCrypto has no Argon2id, so a client written against "what the browser has"
// produces PBKDF2. The constant exists to keep those users openable, and kdf/memory/iterations are
// in the update list precisely so moving them to Argon2id later is a re-wrap on their next login
// rather than a migration. If KDFPBKDF2 were rejected that whole path is dead, and nobody would
// find out until a Safari user tried to enrol.
//
// Covers: E2EE-POL-008
func TestDBE2EEPBKDF2RoundTrip(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "pbkdf2@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey:         []byte("wrapped by a browser with no argon2id"),
		RecoveryWrappedKey: []byte("recovery"),
		Params:             e2ee.Params{KDF: e2ee.KDFPBKDF2, Memory: 65536, Iterations: 3},
	}); err != nil {
		t.Fatalf("a pbkdf2 enrolment was rejected: %v", err)
	}
	first, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if first.KDF != e2ee.KDFPBKDF2 {
		t.Fatalf("kdf = %q after a pbkdf2 Put, want pbkdf2", first.KDF)
	}
	if got := vaultRow(t, f.db, id).KDF; got != e2ee.KDFPBKDF2 {
		t.Errorf("the column holds %q, want pbkdf2", got)
	}

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("re-wrapped under argon2id"), RecoveryWrappedKey: []byte("recovery"),
		Params:     e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3},
		KeyVersion: 1,
	}); err != nil {
		t.Fatalf("the migration re-wrap was rejected: %v", err)
	}
	second, err := v.Params(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	if second.KDF != e2ee.KDFArgon2id {
		t.Errorf("kdf = %q after the re-wrap, want argon2id", second.KDF)
	}
	// A KDF migration that also rotated the salt would destroy the very vaults it was meant to
	// rescue.
	if !bytes.Equal(first.Salt, second.Salt) {
		t.Error("the salt moved across the KDF change")
	}
}

// TestDBE2EERejectionLeavesGoodVaultIntact @notice A rejected write never damages the vault that
// is already there.
//
// @dev Every other rejection case runs against a fresh user with no row, so they all assert
// vaultRows == 0 — which is satisfied by a check that runs *after* the write as easily as before
// it. The failure they miss is the damaging one: a user with a working vault submits a bad re-wrap
// and loses the good key. check does run first, and this case is what says so (mutation M-19).
//
// The count is the wrong instrument here — there is a row. The bytes, the parameters and the
// version are compared, and the version especially: a bumped key_version would lock the client out
// of its next legitimate write.
//
// Covers: E2EE-POL-013
func TestDBE2EERejectionLeavesGoodVaultIntact(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "intact@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	good := []byte("the key the user actually has")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: good, RecoveryWrappedKey: []byte("the recovery wrapping"),
		Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 131072, Iterations: 4},
	}); err != nil {
		t.Fatal(err)
	}
	want := vaultRow(t, f.db, id)

	rejections := map[string]e2ee.Vault{
		"no wrapped key":        {RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1},
		"an empty wrapped key":  {WrappedKey: []byte{}, RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1},
		"blob over the ceiling": {WrappedKey: bytes.Repeat([]byte{0x41}, 8193), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1},
		"recovery over the ceiling": {WrappedKey: []byte("wrapped"),
			RecoveryWrappedKey: bytes.Repeat([]byte{0x41}, 8193), KeyVersion: 1},
		"no recovery wrapping": {WrappedKey: []byte("wrapped"), KeyVersion: 1},
		"an unknown KDF": {WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: "scrypt", Memory: 65536, Iterations: 3}, KeyVersion: 1},
		"memory below the floor": {WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 1024, Iterations: 3}, KeyVersion: 1},
		"iterations below the floor": {WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 1}, KeyVersion: 1},
	}
	for name, vault := range rejections {
		t.Run(name, func(t *testing.T) {
			err := v.Put(uctx, f.db, vault)
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
			got := vaultRow(t, f.db, id)
			if !bytes.Equal(got.WrappedKey, want.WrappedKey) {
				t.Errorf("the stored key changed to %q", got.WrappedKey)
			}
			if !bytes.Equal(got.RecoveryWrappedKey, want.RecoveryWrappedKey) {
				t.Errorf("the recovery wrapping changed to %q", got.RecoveryWrappedKey)
			}
			if got.KDF != want.KDF || got.Memory != want.Memory || got.Iterations != want.Iterations {
				t.Errorf("the parameters changed to %q/%d/%d", got.KDF, got.Memory, got.Iterations)
			}
			if got.KeyVersion != want.KeyVersion {
				t.Errorf("key_version moved from %d to %d — the client is now locked out of its next "+
					"legitimate write", want.KeyVersion, got.KeyVersion)
			}
		})
	}

	// The row was writable all along: without this a Put that is simply broken for this user would
	// pass every arm above.
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("a legitimate re-wrap"), RecoveryWrappedKey: []byte("recovery"),
		KeyVersion: want.KeyVersion,
	}); err != nil {
		t.Fatalf("a valid Put at the same version was rejected: %v", err)
	}
	if got := vaultRow(t, f.db, id); got.KeyVersion != want.KeyVersion+1 {
		t.Errorf("key_version = %d after a valid write, want %d", got.KeyVersion, want.KeyVersion+1)
	}
}

// TestDBE2EEMemoryHasNoCeiling @notice [UNSPECIFIED] Memory has a floor and no ceiling.
//
// @dev §17.12. Memory is uint32 in Go over an int4 column, so a value past 2^31 surfaces as a
// driver error rather than CodeInvalidInput and a consumer's error mapping turns a client's bad
// input into a 500. A merely absurd value that fits — 2 GiB — is accepted, and the user's own
// devices can then never derive their key.
//
// Which error is the finding, so the type is asserted and not just its presence.
//
// Covers: E2EE-POL-014
func TestDBE2EEMemoryHasNoCeiling(t *testing.T) {
	f, v := newVaultFixture(t)

	t.Run("past what the column can hold", func(t *testing.T) {
		const addr = "hugememory@example.test"
		id := f.createPasswordUser(t, addr, "the original password")
		err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 3_000_000_000, Iterations: 3},
		})
		if err == nil {
			t.Fatal("3 GiB of Argon2 memory was accepted and stored")
		}
		var ae *kalerr.Error
		if errors.As(err, &ae) {
			t.Errorf("error = %s, and today this is a raw driver error (§17.12) — if check grew a "+
				"ceiling, move the finding rather than deleting the case", ae.Code)
		}
		if n := vaultRows(t, f.db, id); n != 0 {
			t.Errorf("%d row(s) landed anyway", n)
		}
	})

	t.Run("absurd but within the column", func(t *testing.T) {
		const addr = "absurdmemory@example.test"
		id := f.createPasswordUser(t, addr, "the original password")
		if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 2_000_000, Iterations: 3},
		}); err != nil {
			t.Fatalf("2 GiB was rejected: %v — if that is a new ceiling, §17.12 has been closed", err)
		}
		if got := vaultRow(t, f.db, id).Memory; got != 2_000_000 {
			t.Errorf("stored memory = %d, want 2000000", got)
		}
	})

	// A sane value must succeed, so the case is about the ceiling and not about Put being broken.
	sane := f.createPasswordUser(t, "sanememory@example.test", "the original password")
	if err := v.Put(vaultCtx(sane, "sanememory@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Errorf("an ordinary Put failed: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// §9 · staleness
// ---------------------------------------------------------------------------------------------

// TestDBE2EEStaleAfterReset @notice A password reset makes the vault read as stale, and leaves the
// recovery wrapping intact.
//
// @dev The flag, not the bytes: a test that only checked that password_hash changed would pass
// trivially. Staleness is the whole reason authn needs no hook here — the worst failure in this
// design is a wrapped key handed to a client that has no possible way to open it, producing a
// decrypt error somewhere far away with no explanation.
//
// Covers: E2EE-STL-001, E2EE-STL-002, E2EE-STL-005
func TestDBE2EEStaleAfterReset(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	id := f.createPasswordUser(t, "stale@example.test", "the original password")
	uctx := vaultCtx(id, "stale@example.test")

	recovery := []byte("the vault key under the recovery code")
	wrapped := []byte("the vault key under the password")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: wrapped, RecoveryWrappedKey: recovery,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(uctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("no vault after Put")
	}
	if got.Stale {
		t.Fatal("a freshly written vault reads as stale")
	}

	f.mailer.take()
	if err := f.accounts.RequestPasswordReset(ctx, f.db, "stale@example.test"); err != nil {
		t.Fatal(err)
	}
	token := tokenFromURL(t, f.mailer.take()[0].msg.URL)
	if err := f.accounts.ResetPassword(ctx, f.db, token, "the replacement password"); err != nil {
		t.Fatal(err)
	}

	got, err = v.Get(uctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("the reset removed the vault row")
	}
	if !got.Stale {
		t.Error("the password moved and the vault still reads live")
	}
	// It is wrapped under the code, not under the password, so it survives — and it is the only
	// route back into a vault whose password was reset.
	if !bytes.Equal(got.RecoveryWrappedKey, recovery) {
		t.Error("the recovery wrapping did not survive the reset")
	}
	// kal nulls neither column; a case that only guarded the recovery blob would miss a reset that
	// destroyed the password wrapping.
	if !bytes.Equal(got.WrappedKey, wrapped) {
		t.Error("the password wrapping did not survive the reset")
	}
}

// TestDBE2EEStaleAfterChangePassword @notice The other password-write path produces the same
// verdict.
//
// @dev ChangePassword writes password_hash through a different statement, and the staleness join
// does not care — which is the design's strength and therefore worth one case, because a future
// ChangePassword that wrote through a path the join could not see would be silent.
//
// The fixture's Accounts has a nil SecretShape, so it takes real passwords: running this under
// Config.E2EE semantics would be rejected by the shape check before the hash ever moved, and the
// case would pass for the wrong reason.
//
// Covers: E2EE-STL-003
func TestDBE2EEStaleAfterChangePassword(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "changepw@example.test"
	const password = "the original password"
	id := f.createPasswordUser(t, addr, password)
	uctx := vaultCtx(id, addr)

	recovery := []byte("the recovery wrapping")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: recovery,
	}); err != nil {
		t.Fatal(err)
	}

	rec := f.request(t, "", "192.0.2.90", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, addr, password)
		return err
	})
	token := sessionCookie(rec)
	if token == "" {
		t.Fatal("no cookie from login")
	}

	// A failed change must leave the vault live: the flag tracks the hash, not the call.
	f.request(t, token, "192.0.2.90", func(ctx context.Context) error {
		return f.accounts.ChangePassword(ctx, f.db, "not the password", "a replacement password")
	})
	if f.lastErr == nil {
		t.Fatal("ChangePassword accepted the wrong current password")
	}
	got, err := v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Stale {
		t.Error("a rejected password change staled the vault")
	}

	f.request(t, token, "192.0.2.90", func(ctx context.Context) error {
		return f.accounts.ChangePassword(ctx, f.db, password, "a replacement password")
	})
	if f.lastErr != nil {
		t.Fatalf("ChangePassword: %v", f.lastErr)
	}
	got, err = v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if !got.Stale {
		t.Error("the password changed and the vault still reads live")
	}
	if !bytes.Equal(got.RecoveryWrappedKey, recovery) {
		t.Error("the recovery wrapping did not survive a password change")
	}
}

// TestDBE2EERewrapClearsStale @notice A re-wrap after a reset restores the live verdict.
//
// @dev This closes the recovery loop. wrapped_for is recomputed on the update path — it is in the
// do-update list, and it is the entry most likely to be dropped in a refactor (mutation M-12). If
// it were not, the vault would read stale *forever* after one password reset: the user re-wraps,
// is told the key is still untrustworthy, re-wraps again, and the loop never terminates.
//
// The version comes from Get. Re-wrapping at the wrong one returns CONFLICT, and the case would
// then assert staleness on a vault that was never rewritten and pass for the wrong reason.
//
// Covers: E2EE-STL-004
func TestDBE2EERewrapClearsStale(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "rewrap@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("the original wrapping")); err != nil {
		t.Fatal(err)
	}

	reset := func(next string) {
		t.Helper()
		f.mailer.take()
		if err := f.accounts.RequestPasswordReset(ctx, f.db, addr); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ResetPassword(ctx, f.db,
			tokenFromURL(t, f.mailer.take()[0].msg.URL), next); err != nil {
			t.Fatal(err)
		}
	}

	reset("the replacement password")
	stale, err := v.Get(uctx, f.db)
	if err != nil || stale == nil {
		t.Fatalf("Get = %+v, %v", stale, err)
	}
	if !stale.Stale {
		t.Fatal("the reset did not stale the vault")
	}

	rewrapped := []byte("wrapped under the new password")
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: rewrapped, RecoveryWrappedKey: []byte("recovery"), KeyVersion: stale.KeyVersion,
	}); err != nil {
		t.Fatalf("the re-wrap was rejected: %v", err)
	}
	live, err := v.Get(uctx, f.db)
	if err != nil || live == nil {
		t.Fatalf("Get = %+v, %v", live, err)
	}
	if live.Stale {
		t.Fatal("the vault still reads stale after a re-wrap — the user is now in a loop with no exit")
	}
	if !bytes.Equal(live.WrappedKey, rewrapped) {
		t.Errorf("the stored key is %q, want the re-wrapped one", live.WrappedKey)
	}

	// A second reset must stale it again, which proves the fingerprint tracks the hash rather than
	// being cleared once and left.
	reset("a third password")
	again, err := v.Get(uctx, f.db)
	if err != nil || again == nil {
		t.Fatalf("Get = %+v, %v", again, err)
	}
	if !again.Stale {
		t.Error("a second reset left the vault reading live")
	}
}

// TestDBE2EEStaleIsPerUser @notice One account's password change does not stale another's vault.
//
// @dev The staleness expression joins auth_users on v.user_id. A join written against the wrong
// column, or a fingerprint compared globally, would mark the whole deployment stale the first time
// anyone changed a password — and every client would refuse a key that was perfectly good.
//
// Both users enrol before the reset: enrolling B afterwards would mask a join that ignores
// user_id.
//
// Covers: E2EE-STL-006
func TestDBE2EEStaleIsPerUser(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	aID := f.createPasswordUser(t, "stale-a@example.test", "the original password")
	bID := f.createPasswordUser(t, "stale-b@example.test", "the original password")
	aCtx := vaultCtx(aID, "stale-a@example.test")
	bCtx := vaultCtx(bID, "stale-b@example.test")

	for _, uctx := range []context.Context{aCtx, bCtx} {
		if err := v.Put(uctx, f.db, validVault("wrapped")); err != nil {
			t.Fatal(err)
		}
	}

	f.mailer.take()
	if err := f.accounts.RequestPasswordReset(ctx, f.db, "stale-a@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ResetPassword(ctx, f.db,
		tokenFromURL(t, f.mailer.take()[0].msg.URL), "the replacement password"); err != nil {
		t.Fatal(err)
	}

	a, err := v.Get(aCtx, f.db)
	if err != nil || a == nil {
		t.Fatalf("A: %+v, %v", a, err)
	}
	b, err := v.Get(bCtx, f.db)
	if err != nil || b == nil {
		t.Fatalf("B: %+v, %v", b, err)
	}
	if !a.Stale {
		t.Error("A reset their password and A's vault reads live")
	}
	if b.Stale {
		t.Error("A reset their password and B's vault reads stale — every client in the deployment " +
			"now refuses a key that is perfectly good")
	}
}

// TestDBE2EEStaleWithNoPassword @notice An account with no password has a defined verdict.
//
// @dev coalesce(password_hash, ”) means the fingerprint for an invited user who has not accepted
// is sha256(”), so their vault reads live only if wrapped_for holds that exact digest. IS
// DISTINCT FROM is what stops the comparison evaluating to NULL and scanning into a bool — the
// failure a plain `<>` produces is a scan error, not a wrong answer (mutation M-09).
//
// The user is inserted directly: createPasswordUser sets a hash, which is the state this case is
// not about.
//
// Covers: E2EE-STL-007
func TestDBE2EEStaleWithNoPassword(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "invited@example.test"
	id := createUser(t, f.db, addr)
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, validVault("wrapped before there was a password")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(uctx, f.db)
	if err != nil {
		t.Fatalf("Get with a null password_hash: %v — a plain <> here scans a NULL into a bool", err)
	}
	if got == nil {
		t.Fatal("no vault")
	}
	if got.Stale {
		t.Error("a vault written against a null password reads stale immediately")
	}

	// The negative variant: without it, a Stale that is always false passes.
	if _, err := f.db.Exec(
		`update auth_users set password_hash = 'a hash that was not there before' where id = ?`,
		id); err != nil {
		t.Fatal(err)
	}
	got, err = v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if !got.Stale {
		t.Error("the account gained a password and the vault still reads live")
	}
}

// TestDBE2EEStaleComputedAtWriteTime @notice The fingerprint is the hash as it stands at the
// instant of the write.
//
// @dev Computing wrapped_for in Go requires reading password_hash first, which is a read-then-write
// racing a concurrent password change: the vault is written against a hash that is already gone,
// and it reads stale from the moment it is created.
//
// The racing write is a direct update rather than ChangePassword — ChangePassword needs the
// middleware and the fixture carries its error in a field no goroutine may share. The property is
// the same: the fingerprint must equal one of the two hashes that existed, and the staleness read
// must agree with the one that is current.
//
// A green run is evidence, not proof. The window is small; twenty iterations is what makes a
// Go-side computation likely to be caught rather than certain to be.
//
// Covers: E2EE-STL-008
func TestDBE2EEStaleComputedAtWriteTime(t *testing.T) {
	f, v := newVaultFixture(t)

	// The sequential baseline first: change, then write, always reads live. Without a known-good
	// ordering the racing arm has nothing to compare against.
	base := f.createPasswordUser(t, "writetime-base@example.test", "the original password")
	if _, err := f.db.Exec(`update auth_users set password_hash = 'changed first' where id = ?`, base); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(vaultCtx(base, "writetime-base@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(vaultCtx(base, "writetime-base@example.test"), f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Stale {
		t.Fatal("a vault written after a password change reads stale — the fingerprint is not the " +
			"hash at write time")
	}

	for i := 0; i < 20; i++ {
		email := fmt.Sprintf("writetime-%d@example.test", i)
		id := f.createPasswordUser(t, email, "the original password")
		uctx := vaultCtx(id, email)
		before := passwordHash(t, f.db, id)
		after := fmt.Sprintf("the hash written by iteration %d", i)

		var wg sync.WaitGroup
		start := make(chan struct{})
		var putErr, updateErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, updateErr = f.db.Exec(`update auth_users set password_hash = ? where id = ?`, after, id)
		}()
		go func() {
			defer wg.Done()
			<-start
			putErr = v.Put(uctx, f.db, validVault("wrapped in the race"))
		}()
		close(start)
		wg.Wait()
		if putErr != nil || updateErr != nil {
			t.Fatalf("iteration %d: put %v, update %v", i, putErr, updateErr)
		}

		fingerprint := vaultRow(t, f.db, id).WrappedFor
		oldDigest := sha256.Sum256([]byte(before))
		newDigest := sha256.Sum256([]byte(after))
		// Either ordering is legal; a fingerprint over a third value is not, and that is what a
		// hash read in Go before the statement ran would eventually produce.
		if !bytes.Equal(fingerprint, oldDigest[:]) && !bytes.Equal(fingerprint, newDigest[:]) {
			t.Fatalf("iteration %d: wrapped_for matches neither hash that existed — it was computed "+
				"from something else", i)
		}

		read, err := v.Get(uctx, f.db)
		if err != nil || read == nil {
			t.Fatalf("iteration %d: Get = %+v, %v", i, read, err)
		}
		// The write and the read must agree: the current hash is the one the update left behind.
		if wantStale := !bytes.Equal(fingerprint, newDigest[:]); read.Stale != wantStale {
			t.Fatalf("iteration %d: Stale = %v, and the stored fingerprint says %v — the write and "+
				"the staleness read disagree", i, read.Stale, wantStale)
		}
	}
}

// TestDBE2EEStaleIgnoredOnWrite @notice A client cannot set or clear its own staleness.
//
// @dev If Stale ever became a stored column instead of a computed one, authn would need a hook and
// an ordering requirement between two writes — the thing this design exists to avoid — and a
// client could then mark its own vault fresh. The direction that matters is the clearing one: a
// client setting the flag is only noise.
//
// Covers: E2EE-STL-009
func TestDBE2EEStaleIgnoredOnWrite(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "flag@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), Stale: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Stale {
		t.Error("a client set Stale on write and the read believed it")
	}

	// The arm that matters. After a reset the vault is stale; a write that carries Stale: false and
	// is *rejected* must leave it stale, which is only possible if the field never reaches the row.
	f.mailer.take()
	if err := f.accounts.RequestPasswordReset(ctx, f.db, addr); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ResetPassword(ctx, f.db,
		tokenFromURL(t, f.mailer.take()[0].msg.URL), "the replacement password"); err != nil {
		t.Fatal(err)
	}
	_ = requireConflict(t, v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("clearing my own flag"), RecoveryWrappedKey: []byte("recovery"),
		Stale: false, KeyVersion: 99,
	}))
	got, err = v.Get(uctx, f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if !got.Stale {
		t.Error("a rejected write carrying Stale: false cleared the flag")
	}

	// And structurally: there is no column for a client to write to.
	var columns int
	if _, err := f.db.QueryOne(pg.Scan(&columns),
		`select count(*) from information_schema.columns
		  where table_schema = ? and table_name = 'auth_e2ee_vaults' and column_name = 'stale'`,
		testSchema); err != nil {
		t.Fatal(err)
	}
	if columns != 0 {
		t.Error("auth_e2ee_vaults grew a stale column — the verdict is computed from the password " +
			"hash, and storing it needs a hook into authn and an ordering rule between two writes")
	}
}

// ---------------------------------------------------------------------------------------------
// §10 · the auth secret and the authn seam
// ---------------------------------------------------------------------------------------------

// e2eeAuthFixture @notice A kal.Auth wired through Config.E2EE, plus the middleware the credential
// flows expect to run inside.
//
// @dev Built through kal.New rather than by hand: the seam this group is about is the one wiring
// closes — Config.E2EE sets both Auth.Vaults and Accounts.SecretShape, and a case that constructed
// Accounts directly would not exercise it.
type e2eeAuthFixture struct {
	db      *pg.DB
	auth    *kal.Auth
	mailer  *recordingMailer
	opts    *kal.VaultOptions
	lastErr error
}

// newE2EEAuthFixture @notice kal.New with client-side encryption switched on, against the scratch
// schema.
func newE2EEAuthFixture(t *testing.T) *e2eeAuthFixture {
	t.Helper()
	db := testDB(t)
	f := &e2eeAuthFixture{
		db:     db,
		mailer: &recordingMailer{},
		opts:   &kal.VaultOptions{Pepper: vaultPepper},
	}
	auth, err := kal.New(kal.Config{
		DB: db, BaseURL: "https://app.example.test", Mailer: f.mailer,
		// Deliberately cheap: these cases exercise which check fires, not what it costs.
		Argon2: authn.Params{Memory: 8192, Time: 1}, TableSchema: testSchema, E2EE: f.opts,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.auth = auth
	return f
}

// request @notice Runs fn as a resolver would: inside kal's own middleware, with a cookie jar.
func (f *e2eeAuthFixture) request(t *testing.T, cookie, ip string, fn func(ctx context.Context) error) *httptest.ResponseRecorder {
	t.Helper()
	var inner error
	h := f.auth.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner = fn(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	if ip != "" {
		req.RemoteAddr = ip + ":40000"
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	f.lastErr = inner
	return rec
}

// authSecret @notice A well-formed client-derived secret, distinct per call.
//
// @dev The server never sees the password behind one of these, which is the whole feature and the
// reason a password policy no longer applies (gotcha 76).
func authSecret(t *testing.T) string {
	t.Helper()
	secret, _ := randomAuthSecret(t)
	return secret
}

// userIDByEmail @notice The account id for an address, for the flows that do not return one.
func userIDByEmail(t *testing.T, db *pg.DB, email string) string {
	t.Helper()
	var id string
	if _, err := db.QueryOne(pg.Scan(&id),
		`select id from auth_users where lower(email) = ?`, strings.ToLower(email)); err != nil {
		t.Fatal(err)
	}
	return id
}

// userRows @notice How many live rows exist for an address.
func userRows(t *testing.T, db *pg.DB, email string) int {
	t.Helper()
	var n int
	if _, err := db.QueryOne(pg.Scan(&n),
		`select count(*) from auth_users where lower(email) = ?`, strings.ToLower(email)); err != nil {
		t.Fatal(err)
	}
	return n
}

// unconsumedTokens @notice How many of a purpose's tokens are still usable.
func unconsumedTokens(t *testing.T, db *pg.DB, purpose string) int {
	t.Helper()
	var n int
	if _, err := db.QueryOne(pg.Scan(&n),
		`select count(*) from auth_tokens where purpose = ? and consumed_at is null`,
		purpose); err != nil {
		t.Fatal(err)
	}
	return n
}

// markVerified @notice Confirms an address without going through the emailed link.
func markVerified(t *testing.T, db *pg.DB, email string) {
	t.Helper()
	if _, err := db.Exec(`update auth_users set email_verified = true where lower(email) = ?`,
		strings.ToLower(email)); err != nil {
		t.Fatal(err)
	}
}

// TestDBE2EERegisterUnderE2EE @notice A raw password on the registration path creates no account.
//
// @dev The first gate a mis-updated client hits. If the check ran after the insert — or if the row
// were created and only the hash rejected — the address would now be taken, the user could not
// register again, and support would have an account nobody can log into. The row is the property;
// the error code is the symptom.
//
// Covers: E2EE-SEC-009, E2EE-SHM-005
func TestDBE2EERegisterUnderE2EE(t *testing.T) {
	f := newE2EEAuthFixture(t)
	ctx := context.Background()
	const addr = "register@example.test"

	if f.auth.Vaults == nil {
		t.Fatal("Config.E2EE is set and Auth.Vaults is nil — half the wiring is missing, and the " +
			"missing half is the one that is silent")
	}

	err := f.auth.Accounts.Register(ctx, f.db, addr, "a perfectly good password")
	requireErrorCode(t, err, kalerr.CodeInvalidInput)
	if n := userRows(t, f.db, addr); n != 0 {
		t.Fatalf("the registration was rejected and %d account row(s) exist — the address is now "+
			"taken by an account nobody can log into", n)
	}

	// The negative variant: without it a Register that always fails would pass.
	if err := f.auth.Accounts.Register(ctx, f.db, addr, authSecret(t)); err != nil {
		t.Fatalf("Register with a valid auth secret: %v", err)
	}
	if n := userRows(t, f.db, addr); n != 1 {
		t.Errorf("%d rows after a valid registration, want 1", n)
	}
}

// TestDBE2EEResetPasswordUnderE2EE @notice A raw password on the reset path does not burn the
// token.
//
// @dev The shape check is the first statement in ResetPassword, before consume. If it moved after
// — an ordering nothing outside this case pins — a client that sent a raw password would burn the
// user's one-shot token, leave the password unchanged, and leave the user with no way to retry:
// the token is gone, the password is the one they have forgotten, and the vault is untouched but
// unreachable.
//
// The second call reuses the *same* token deliberately. Requesting a fresh one is exactly what
// would hide the finding.
//
// Covers: E2EE-SEC-010
func TestDBE2EEResetPasswordUnderE2EE(t *testing.T) {
	f := newE2EEAuthFixture(t)
	ctx := context.Background()
	const addr = "reset-shape@example.test"

	if err := f.auth.Accounts.Register(ctx, f.db, addr, authSecret(t)); err != nil {
		t.Fatal(err)
	}
	markVerified(t, f.db, addr)
	id := userIDByEmail(t, f.db, addr)
	if err := f.auth.Vaults.Put(vaultCtx(id, addr), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	hashBefore := passwordHash(t, f.db, id)

	f.mailer.take()
	if err := f.auth.Accounts.RequestPasswordReset(ctx, f.db, addr); err != nil {
		t.Fatal(err)
	}
	token := tokenFromURL(t, f.mailer.take()[0].msg.URL)

	err := f.auth.Accounts.ResetPassword(ctx, f.db, token, "a perfectly good password")
	requireErrorCode(t, err, kalerr.CodeInvalidInput)
	if n := unconsumedTokens(t, f.db, "reset"); n != 1 {
		t.Fatalf("%d unconsumed reset tokens after a rejected reset, want 1 — the user's only route "+
			"back has been spent on a client-side mistake", n)
	}
	if passwordHash(t, f.db, id) != hashBefore {
		t.Error("the rejected reset moved the stored hash")
	}
	got, err := f.auth.Vaults.Get(vaultCtx(id, addr), f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Stale {
		t.Error("a rejected reset staled the vault")
	}

	if err := f.auth.Accounts.ResetPassword(ctx, f.db, token, authSecret(t)); err != nil {
		t.Fatalf("the same token was refused on the second attempt: %v", err)
	}
	if passwordHash(t, f.db, id) == hashBefore {
		t.Error("the accepted reset did not move the hash")
	}
}

// TestDBE2EEAcceptInviteUnderE2EE @notice A raw password on the invite path does not burn the
// invite.
//
// @dev An invite is single-use and often the only one a person will get. Burning it on a shape
// rejection means re-inviting through an administrator, and under E2EE the invited user has no
// vault yet — so the failure is recoverable only by a human.
//
// Covers: E2EE-SEC-011
func TestDBE2EEAcceptInviteUnderE2EE(t *testing.T) {
	f := newE2EEAuthFixture(t)
	ctx := context.Background()
	const addr = "invited-shape@example.test"

	link, err := f.auth.Accounts.Invite(ctx, f.db, addr)
	if err != nil {
		t.Fatal(err)
	}
	token := tokenFromURL(t, link)
	id := userIDByEmail(t, f.db, addr)

	err = f.auth.Accounts.AcceptInvite(ctx, f.db, token, "a perfectly good password")
	requireErrorCode(t, err, kalerr.CodeInvalidInput)
	if n := unconsumedTokens(t, f.db, "invite"); n != 1 {
		t.Fatalf("%d unconsumed invites after a rejected acceptance, want 1", n)
	}
	if hash := passwordHash(t, f.db, id); hash != "" {
		t.Errorf("the rejected acceptance set a credential: %q", hash)
	}

	if err := f.auth.Accounts.AcceptInvite(ctx, f.db, token, authSecret(t)); err != nil {
		t.Fatalf("the same invite was refused on the second attempt: %v", err)
	}
	if hash := passwordHash(t, f.db, id); hash == "" {
		t.Error("the accepted invite set no credential")
	}
}

// TestDBE2EEChangePasswordUnderE2EE @notice The shape check applies to the replacement and not to
// the value being replaced.
//
// @dev Both halves matter. `next` unchecked is silent data loss on the most common vault-affecting
// operation. `current` checked would be worse in a different way: an account enrolled before E2EE
// was switched on still holds a password-derived hash, and shape-checking `current` locks that user
// out permanently with INVALID_INPUT — no migration path, and no way for them to reach the very
// operation that would fix it.
//
// The two error codes are the entire finding. An implementation that rejected both looks identical
// under a bare non-nil check.
//
// Covers: E2EE-SEC-012
func TestDBE2EEChangePasswordUnderE2EE(t *testing.T) {
	f := newE2EEAuthFixture(t)
	ctx := context.Background()
	const addr = "change-shape@example.test"
	first := authSecret(t)

	if err := f.auth.Accounts.Register(ctx, f.db, addr, first); err != nil {
		t.Fatal(err)
	}
	markVerified(t, f.db, addr)
	id := userIDByEmail(t, f.db, addr)
	if err := f.auth.Vaults.Put(vaultCtx(id, addr), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	hashBefore := passwordHash(t, f.db, id)

	rec := f.request(t, "", "192.0.2.100", func(reqCtx context.Context) error {
		_, err := f.auth.Accounts.Login(reqCtx, f.db, addr, first)
		return err
	})
	if f.lastErr != nil {
		t.Fatalf("Login with the auth secret: %v", f.lastErr)
	}
	cookie := sessionCookie(rec)
	if cookie == "" {
		t.Fatal("no cookie from login")
	}

	f.request(t, cookie, "192.0.2.100", func(reqCtx context.Context) error {
		return f.auth.Accounts.ChangePassword(reqCtx, f.db, first, "a perfectly good password")
	})
	requireErrorCode(t, f.lastErr, kalerr.CodeInvalidInput)
	if passwordHash(t, f.db, id) != hashBefore {
		t.Error("a rejected next-secret still moved the hash")
	}
	got, err := f.auth.Vaults.Get(vaultCtx(id, addr), f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if got.Stale {
		t.Error("a rejected change staled the vault")
	}

	second := authSecret(t)
	f.request(t, cookie, "192.0.2.101", func(reqCtx context.Context) error {
		return f.auth.Accounts.ChangePassword(reqCtx, f.db, "whatever shape this is", second)
	})
	// Reaches the verifier: current is passed through unexamined, which is what keeps a
	// pre-E2EE account able to change its own credential.
	requireErrorCode(t, f.lastErr, kalerr.CodeInvalidCredentials)

	f.request(t, cookie, "192.0.2.100", func(reqCtx context.Context) error {
		return f.auth.Accounts.ChangePassword(reqCtx, f.db, first, second)
	})
	if f.lastErr != nil {
		t.Fatalf("the correct current secret with a valid next was rejected: %v", f.lastErr)
	}
	got, err = f.auth.Vaults.Get(vaultCtx(id, addr), f.db)
	if err != nil || got == nil {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if !got.Stale {
		t.Error("the credential moved and the vault still reads live")
	}
}

// TestDBE2EELoginDoesNotShapeCheck @notice Login accepts any shape and answers
// INVALID_CREDENTIALS, deliberately.
//
// @dev Both directions are real, and this case exists so nobody "hardens" the one that looks
// untidy. If Login shape-checked, every account that registered before E2EE was enabled would be
// locked out at the login screen with INVALID_INPUT — and the reset path would not save them,
// because that path requires an auth secret too. That it silently *accepts* a raw password is not
// a hole: the write-side checks are what prevent an account hashed over a raw password existing in
// the first place. The control is on the write path only (mutation M-34, §17.13).
//
// Covers: E2EE-SEC-013
func TestDBE2EELoginDoesNotShapeCheck(t *testing.T) {
	f := newE2EEAuthFixture(t)
	ctx := context.Background()
	const addr = "login-shape@example.test"
	secret := authSecret(t)

	if err := f.auth.Accounts.Register(ctx, f.db, addr, secret); err != nil {
		t.Fatal(err)
	}
	markVerified(t, f.db, addr)

	// A distinct address per attempt is not possible here — the account is the subject — so each
	// failure gets its own IP, and the counters are cleared before the success. TestDBLoginBackoff
	// is where the throttle itself is pinned; inside an open window even a correct credential is
	// refused, which would mask what this case is about.
	for name, credential := range map[string]string{
		"a raw password":          "a perfectly good password",
		"a well-formed but wrong": authSecret(t),
		"not even close":          "",
	} {
		f.request(t, "", "198.51.100.200", func(reqCtx context.Context) error {
			_, err := f.auth.Accounts.Login(reqCtx, f.db, addr, credential)
			return err
		})
		var ae *kalerr.Error
		if !errors.As(f.lastErr, &ae) {
			t.Fatalf("%s: error = %v, want a *kalerr.Error", name, f.lastErr)
		}
		if ae.Code == kalerr.CodeInvalidInput {
			t.Errorf("%s: login answered INVALID_INPUT — every account created before E2EE was "+
				"enabled is now locked out with no route back", name)
		}
		if ae.Code != kalerr.CodeInvalidCredentials {
			t.Errorf("%s: code = %s, want INVALID_CREDENTIALS", name, ae.Code)
		}
		// Cleared between attempts so each one is the account's first failure: inside an open
		// backoff window even a correct credential is refused, and the arm below needs one.
		if _, err := f.db.Exec(`delete from auth_login_attempts`); err != nil {
			t.Fatal(err)
		}
	}

	// Without this arm a Login that rejects everything would pass.
	var principal *authz.Principal
	f.request(t, "", "198.51.100.201", func(reqCtx context.Context) error {
		var err error
		principal, err = f.auth.Accounts.Login(reqCtx, f.db, addr, secret)
		return err
	})
	if f.lastErr != nil || principal == nil {
		t.Fatalf("the correct auth secret did not log in: %v", f.lastErr)
	}
}

// TestDBE2EEZeroConfigKeepsPasswordPolicy @notice With Config.E2EE nil nothing about authn changes,
// and with it set the policy is replaced rather than removed.
//
// @dev If SecretShape defaulted to nil-and-skipped rather than to ValidatePassword, enabling
// nothing would silently remove the password policy from every existing deployment (mutation
// M-35). The other direction is gotcha 76: under E2EE the server never sees a password, so a
// strength check is not merely useless but wrong — and the consequence is asserted here rather
// than assumed, by showing that the two configurations reject the same short string for two
// different reasons.
//
// Covers: E2EE-SEC-014, E2EE-SEC-015, E2EE-SHM-004
func TestDBE2EEZeroConfigKeepsPasswordPolicy(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	plain, err := kal.New(kal.Config{
		DB: db, BaseURL: "https://app.example.test", Mailer: &recordingMailer{},
		Argon2: authn.Params{Memory: 8192, Time: 1}, TableSchema: testSchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Vaults != nil {
		t.Error("the vault is on without Config.E2EE — it must be opt-in")
	}

	shortErr := plain.Accounts.Register(ctx, db, "short@example.test", "short")
	requireErrorCode(t, shortErr, kalerr.CodeInvalidInput)
	if n := userRows(t, db, "short@example.test"); n != 0 {
		t.Errorf("%d rows for an address whose registration was rejected", n)
	}
	if err := plain.Accounts.Register(ctx, db, "policy-ok@example.test", "a password worth using"); err != nil {
		t.Fatalf("an ordinary password was rejected with E2EE off: %v", err)
	}

	encrypted, err := kal.New(kal.Config{
		DB: db, BaseURL: "https://app.example.test", Mailer: &recordingMailer{},
		Argon2: authn.Params{Memory: 8192, Time: 1}, TableSchema: testSchema,
		E2EE: &kal.VaultOptions{Pepper: vaultPepper},
	})
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.Vaults == nil {
		t.Fatal("Config.E2EE is set and Auth.Vaults is nil")
	}

	shapeErr := encrypted.Accounts.Register(ctx, db, "short-e2ee@example.test", "short")
	requireErrorCode(t, shapeErr, kalerr.CodeInvalidInput)
	// Both fail, so the codes cannot distinguish them: the message is what says which control
	// fired, and the distinction is the case.
	if shapeErr.Error() == shortErr.Error() {
		t.Errorf("both configurations reject a short password with the identical message %q — one of "+
			"the two checks is not running", shapeErr)
	}

	// A well-formed auth secret is accepted with no strength check anywhere in the path. What the
	// user typed behind it is unknowable to this side, which is gotcha 76 and a documented loss.
	if err := encrypted.Accounts.Register(ctx, db, "secret-ok@example.test", authSecret(t)); err != nil {
		t.Fatalf("a valid auth secret was rejected: %v", err)
	}
	// And the shape check is a real replacement, not an absence.
	requireErrorCode(t,
		encrypted.Accounts.Register(ctx, db, "raw-ok@example.test", "a password worth using"),
		kalerr.CodeInvalidInput)
}

// TestDBE2EEShimSchemaOverride @notice Config.TableSchema wins over Options.Schema, and the
// caller's own struct is not rewritten.
//
// @dev A consumer that sets E2EE.Schema and not Config.TableSchema would otherwise get statements
// against the default schema with no warning — every vault operation silently targeting the wrong
// tables, which under a shared database is another tenant's. kal takes a copy so the discarded
// value is at least still the consumer's; a version that wrote through the pointer would change a
// struct they still hold.
//
// Covers: E2EE-SHM-006
func TestDBE2EEShimSchemaOverride(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	const addr = "schema-override@example.test"

	opts := &kal.VaultOptions{Pepper: vaultPepper, Schema: "somewhere_else"}
	auth, err := kal.New(kal.Config{
		DB: db, BaseURL: "https://app.example.test", Mailer: &recordingMailer{},
		Argon2: authn.Params{Memory: 8192, Time: 1}, TableSchema: testSchema, E2EE: opts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Schema != "somewhere_else" {
		t.Errorf("kal.New rewrote the caller's Options.Schema to %q", opts.Schema)
	}

	if err := auth.Accounts.Register(ctx, db, addr, authSecret(t)); err != nil {
		t.Fatal(err)
	}
	id := userIDByEmail(t, db, addr)
	if err := auth.Vaults.Put(vaultCtx(id, addr), db, validVault("wrapped")); err != nil {
		t.Fatalf("Put against the overridden schema: %v", err)
	}
	var n int
	if _, err := db.QueryOne(pg.Scan(&n),
		`select count(*) from ?.auth_e2ee_vaults where user_id = ?`, pg.Ident(testSchema), id); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows in %s.auth_e2ee_vaults, want 1 — the vault landed somewhere else", n, testSchema)
	}
}

// ---------------------------------------------------------------------------------------------
// §11 · the recovery code
// ---------------------------------------------------------------------------------------------

// TestDBE2EERecoveryCodeIsNeverStored @notice No hash or copy of a recovery code reaches any table.
//
// @dev NewRecoveryCode calls session.NewToken, which returns (code, hash, err), and discards the
// hash. Storing it "so we can tell the user whether their code is right" is a natural and fatal
// convenience: it gives a stolen database a second, verifiable route into every vault, which is
// precisely the property this design forgoes. The failing version is a one-line change in a
// package that already computes the hash (mutation M-29).
//
// Every table and every text or bytea column is enumerated from the catalogue, so a table added by
// a later migration is covered by construction rather than by somebody remembering to extend a
// list.
//
// Covers: E2EE-RCV-003
func TestDBE2EERecoveryCodeIsNeverStored(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "recovery-scan@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	code, err := kal.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	// Derived from the code, not containing it: a blob that embedded the code would make the scan
	// below find it and the case would report the wrong finding.
	digest := sha256.Sum256([]byte("wrap|" + code))
	recovery := digest[:]
	if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped under the password"), RecoveryWrappedKey: recovery,
	}); err != nil {
		t.Fatal(err)
	}

	type column struct {
		TableName  string
		ColumnName string
		DataType   string
	}
	var columns []column
	if _, err := f.db.Query(&columns,
		`select table_name, column_name, data_type from information_schema.columns
		  where table_schema = ? and data_type in ('text', 'character varying', 'bytea')
		  order by table_name, column_name`, testSchema); err != nil {
		t.Fatal(err)
	}
	if len(columns) == 0 {
		t.Fatal("the catalogue query found no columns — the scan below would pass over nothing")
	}

	// find @notice Rows in one column containing needle, for whichever of the two shapes it is.
	find := func(c column, textNeedle string, byteNeedle []byte) int {
		t.Helper()
		var n int
		var err error
		if c.DataType == "bytea" {
			_, err = f.db.QueryOne(pg.Scan(&n),
				`select count(*) from ? where position(?::bytea in coalesce(?, ''::bytea)) > 0`,
				pg.Ident(c.TableName), byteNeedle, pg.Ident(c.ColumnName))
		} else {
			_, err = f.db.QueryOne(pg.Scan(&n),
				`select count(*) from ? where position(? in coalesce(?, '')) > 0`,
				pg.Ident(c.TableName), textNeedle, pg.Ident(c.ColumnName))
		}
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	hash := session.HashToken(code)
	for _, c := range columns {
		if n := find(c, code, []byte(code)); n != 0 {
			t.Errorf("%s.%s holds the recovery code itself in %d row(s)", c.TableName, c.ColumnName, n)
		}
		// Raw in a bytea column, and both encodings a text column would plausibly hold it in.
		for _, encoded := range []string{
			fmt.Sprintf("%x", hash), base64.RawURLEncoding.EncodeToString(hash),
		} {
			if n := find(c, encoded, hash); n != 0 {
				t.Errorf("%s.%s holds a hash of the recovery code in %d row(s) — a stolen database "+
					"now contains a verifiable second route into every vault",
					c.TableName, c.ColumnName, n)
			}
		}
	}

	// The negative variant: a value that *is* stored must be found, or a scan silently looking in
	// the wrong place passes. Only the bytea columns are searched for it — the blob is a digest,
	// not text, and handing arbitrary bytes to Postgres as a text parameter is an encoding error
	// rather than a finding.
	found := false
	for _, c := range columns {
		if c.TableName == "auth_e2ee_vaults" && c.DataType == "bytea" && find(c, "", recovery) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("the scan could not find the wrapped blob it just wrote — it is looking in the wrong place")
	}
}

// TestDBE2EERecoveryCodeWritesNothing @notice Minting a code touches no table.
//
// @dev A version that recorded issuance would reintroduce the stored verifier by the back door:
// "we only store when it was issued" becomes "and its hash, for support".
//
// Covers: E2EE-RCV-004
func TestDBE2EERecoveryCodeWritesNothing(t *testing.T) {
	f, v := newVaultFixture(t)
	before := tableCounts(t, f.db)

	for i := 0; i < 100; i++ {
		if _, err := kal.NewRecoveryCode(); err != nil {
			t.Fatal(err)
		}
	}
	for name, count := range tableCounts(t, f.db) {
		if before[name] != count {
			t.Errorf("%s went from %d rows to %d while minting a hundred codes", name, before[name], count)
		}
	}

	// Without a write that does move a count, this passes against a counter that counts nothing.
	id := f.createPasswordUser(t, "mint@example.test", "the original password")
	if err := v.Put(vaultCtx(id, "mint@example.test"), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if after := tableCounts(t, f.db)["auth_e2ee_vaults"]; after != before["auth_e2ee_vaults"]+1 {
		t.Errorf("auth_e2ee_vaults = %d after a Put, want %d", after, before["auth_e2ee_vaults"]+1)
	}
}

// TestDBE2EERecoveryPathEndToEnd @notice The route back into a vault whose password was reset,
// as one sequence.
//
// @dev Three properties are each asserted elsewhere and never as a chain: the recovery wrapping
// survives the reset, the vault is marked stale, and a re-wrap clears it. A break anywhere leaves
// the user with a vault they can see and cannot open, and the failure only appears end to end.
//
// Covers: E2EE-RCV-005
func TestDBE2EERecoveryPathEndToEnd(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()
	const addr = "recovery-path@example.test"
	id := f.createPasswordUser(t, addr, "the original password")
	uctx := vaultCtx(id, addr)

	code, err := kal.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("wrap|" + code))
	recovery := digest[:]
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped under the password"), RecoveryWrappedKey: recovery,
	}); err != nil {
		t.Fatal(err)
	}

	f.mailer.take()
	if err := f.accounts.RequestPasswordReset(ctx, f.db, addr); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ResetPassword(ctx, f.db,
		tokenFromURL(t, f.mailer.take()[0].msg.URL), "the replacement password"); err != nil {
		t.Fatal(err)
	}

	stale, err := v.Get(uctx, f.db)
	if err != nil || stale == nil {
		t.Fatalf("Get = %+v, %v", stale, err)
	}
	if !stale.Stale {
		t.Fatal("the vault does not report that its password moved")
	}
	if !bytes.Equal(stale.RecoveryWrappedKey, recovery) {
		t.Fatal("the recovery wrapping did not survive the reset — there is now no route back at all")
	}

	// The client unwraps with the code and re-wraps under the new password. kal sees only the
	// second half of that.
	if err := v.Put(uctx, f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped under the replacement password"), RecoveryWrappedKey: recovery,
		KeyVersion: stale.KeyVersion,
	}); err != nil {
		t.Fatalf("the recovery re-wrap was rejected: %v", err)
	}
	live, err := v.Get(uctx, f.db)
	if err != nil || live == nil {
		t.Fatalf("Get = %+v, %v", live, err)
	}
	if live.Stale {
		t.Error("the vault still reads stale after the recovery re-wrap")
	}

	// What the opt-out costs, asserted rather than described: this user reaches the same reset with
	// nothing to unwrap with.
	t.Run("without a recovery wrapping there is no route back", func(t *testing.T) {
		noRecovery := f.vaultsWith(t, e2ee.Options{AllowNoRecovery: true})
		const lonely = "no-recovery@example.test"
		lid := f.createPasswordUser(t, lonely, "the original password")
		lctx := vaultCtx(lid, lonely)
		if err := noRecovery.Put(lctx, f.db, e2ee.Vault{WrappedKey: []byte("wrapped")}); err != nil {
			t.Fatalf("AllowNoRecovery did not allow a vault with no recovery wrapping: %v", err)
		}

		f.mailer.take()
		if err := f.accounts.RequestPasswordReset(ctx, f.db, lonely); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ResetPassword(ctx, f.db,
			tokenFromURL(t, f.mailer.take()[0].msg.URL), "the replacement password"); err != nil {
			t.Fatal(err)
		}
		got, err := noRecovery.Get(lctx, f.db)
		if err != nil || got == nil {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if !got.Stale {
			t.Error("the vault does not report that its password moved")
		}
		if len(got.RecoveryWrappedKey) != 0 {
			t.Errorf("a recovery wrapping appeared from somewhere: %q", got.RecoveryWrappedKey)
		}
		// The data is gone. Nothing in kal can recover it, and that is the documented cost of the
		// opt-out rather than a bug this case is reporting.
	})

	// The same vault written through the default configuration is refused, or the opt-out proves
	// nothing.
	strict := f.createPasswordUser(t, "strict@example.test", "the original password")
	requireErrorCode(t,
		v.Put(vaultCtx(strict, "strict@example.test"), f.db, e2ee.Vault{WrappedKey: []byte("wrapped")}),
		kalerr.CodeInvalidInput)
}

// TestDBE2EERecoveryCodeIsNotASession @notice A recovery code presented as a session cookie
// authenticates nobody.
//
// @dev The two share a shape and a generator. If a code were ever inserted into auth_sessions — by
// a helpful "let them in after recovery" path — it would become a bearer credential with no expiry
// and no revocation.
//
// The principal is asserted, not the error: the middleware never returns one for a bad cookie,
// because anonymous is not an error.
//
// Covers: E2EE-RCV-006
func TestDBE2EERecoveryCodeIsNotASession(t *testing.T) {
	f, _ := newVaultFixture(t)
	const addr = "code-as-cookie@example.test"
	f.createPasswordUser(t, addr, "the original password")

	code, err := kal.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, code, "192.0.2.110", func(ctx context.Context) error {
		if p, ok := authz.From(ctx); ok {
			t.Errorf("a recovery code authenticated as %+v", p)
		}
		return nil
	})
	var sessions int
	if _, err := f.db.QueryOne(pg.Scan(&sessions),
		`select count(*) from auth_sessions where token_sha256 = ?`, session.HashToken(code)); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Error("a session row matches the recovery code")
	}

	// A genuine token through the same path must authenticate, or this passes against a middleware
	// that resolves nobody at all.
	rec := f.request(t, "", "192.0.2.111", func(ctx context.Context) error {
		_, err := f.accounts.Login(ctx, f.db, addr, "the original password")
		return err
	})
	token := sessionCookie(rec)
	if token == "" {
		t.Fatal("no cookie from login")
	}
	f.request(t, token, "192.0.2.111", func(ctx context.Context) error {
		if _, ok := authz.From(ctx); !ok {
			t.Error("a real session token did not authenticate")
		}
		return nil
	})
}

// ---------------------------------------------------------------------------------------------
// §12 · the schema
// ---------------------------------------------------------------------------------------------

// TestDBE2EEParallelismConstraint @notice The database refuses any parallelism but 1.
//
// @dev Gotcha 66, last line of defence. Three mechanisms pin p = 1 — withDefaults, the SQL literal
// and this constraint — and the constraint is the only one that survives a bug in the other two. A
// migration that dropped it would be invisible (mutation M-36).
//
// The insert is raw on purpose: Put hard-codes the literal 1 and can never reach the constraint,
// so a case that went through Put would be asserting something else entirely.
//
// Covers: E2EE-SCH-001
func TestDBE2EEParallelismConstraint(t *testing.T) {
	f := newAuthnFixture(t)

	for _, p := range []int{2, 0} {
		id := f.createPasswordUser(t, fmt.Sprintf("parallel-%d@example.test", p), "the original password")
		cols := directVaultColumns(id)
		cols["parallelism"] = p
		if err := putVaultDirect(f.db, cols); err == nil {
			t.Errorf("the database accepted parallelism = %d — Argon2's p changes the output, so this "+
				"user's laptop and phone now derive different keys", p)
		}
	}

	// 1 must succeed, or a broken insert statement passes both arms above.
	id := f.createPasswordUser(t, "parallel-1@example.test", "the original password")
	if err := putVaultDirect(f.db, directVaultColumns(id)); err != nil {
		t.Errorf("the direct insert is broken, so the rejections above prove nothing: %v", err)
	}
}

// TestDBE2EEParallelismAlwaysOne @notice No Put can produce a parallelism other than 1, on either
// path, and every projection says so.
//
// @dev The client-facing half of gotcha 66. A browser that picks p from the thread pool derives a
// different key on a laptop than on a phone, and the second device reports a corrupt vault.
// withDefaults pins it, the SQL literal pins it, and the update set omits the column entirely —
// three independent reasons, none of which was tested (mutation M-01).
//
// The column being right is useless if the projection is wrong, and it is the projection a client
// reads.
//
// Covers: E2EE-SCH-002
func TestDBE2EEParallelismAlwaysOne(t *testing.T) {
	f, v := newVaultFixture(t)
	ctx := context.Background()

	for _, asked := range []uint8{0, 2, 4, 255} {
		email := fmt.Sprintf("p-%d@example.test", asked)
		id := f.createPasswordUser(t, email, "the original password")
		uctx := vaultCtx(id, email)

		if err := v.Put(uctx, f.db, e2ee.Vault{
			WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params: e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Parallelism: asked},
		}); err != nil {
			t.Fatalf("parallelism %d: Put: %v", asked, err)
		}
		// The update path is a different statement with a different column list.
		if err := v.Put(uctx, f.db, e2ee.Vault{
			WrappedKey: []byte("re-wrapped"), RecoveryWrappedKey: []byte("recovery"),
			Params:     e2ee.Params{KDF: e2ee.KDFArgon2id, Memory: 65536, Iterations: 3, Parallelism: asked},
			KeyVersion: 1,
		}); err != nil {
			t.Fatalf("parallelism %d: re-wrap: %v", asked, err)
		}

		if got := vaultRow(t, f.db, id).Parallelism; got != 1 {
			t.Errorf("parallelism %d: the column holds %d", asked, got)
		}
		params, err := v.Params(ctx, f.db, email)
		if err != nil {
			t.Fatal(err)
		}
		if params.Parallelism != 1 {
			t.Errorf("parallelism %d: Params reports %d", asked, params.Parallelism)
		}
		got, err := v.Get(uctx, f.db)
		if err != nil || got == nil {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if got.Params.Parallelism != 1 {
			t.Errorf("parallelism %d: Get reports %d", asked, got.Params.Parallelism)
		}
	}
}

// TestDBE2EEOneVaultPerUser @notice The primary key makes a second row impossible.
//
// @dev Two rows for one user means Get's QueryOne errors and the vault is unreachable — a denial
// of service on their own data, triggered by whichever write path lost the uniqueness.
//
// Covers: E2EE-SCH-003
func TestDBE2EEOneVaultPerUser(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "onerow@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	if err := putVaultDirect(f.db, directVaultColumns(id)); err != nil {
		t.Fatal(err)
	}
	if err := putVaultDirect(f.db, directVaultColumns(id)); err == nil {
		t.Error("a second vault row was accepted for one user")
	}
	if n := vaultRows(t, f.db, id); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}

	// Through the normal path the second write is an upsert and must succeed, so the case
	// distinguishes the constraint from the code that works around it.
	if err := v.Put(vaultCtx(id, addr), f.db, e2ee.Vault{
		WrappedKey: []byte("wrapped"), RecoveryWrappedKey: []byte("recovery"), KeyVersion: 1,
	}); err != nil {
		t.Errorf("Put over an existing row: %v", err)
	}
}

// TestDBE2EEUserDeleteCascades @notice A hard delete takes the wrapped key with the account.
//
// @dev An orphaned vault row is ciphertext material outliving its owner in a database whose whole
// threat model is "someone reads it", and a dangling user_id breaks every join in sql.go.
//
// A soft delete has the opposite semantics and must leave the row — conflating the two would pin
// the wrong one.
//
// Covers: E2EE-SCH-004
func TestDBE2EEUserDeleteCascades(t *testing.T) {
	f, v := newVaultFixture(t)

	const hard = "hard-delete@example.test"
	hardID := f.createPasswordUser(t, hard, "the original password")
	if err := v.Put(vaultCtx(hardID, hard), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`delete from auth_users where id = ?`, hardID); err != nil {
		t.Fatal(err)
	}
	if n := vaultRows(t, f.db, hardID); n != 0 {
		t.Errorf("%d vault row(s) outlived the account they belong to", n)
	}

	const soft = "soft-delete@example.test"
	softID := f.createPasswordUser(t, soft, "the original password")
	if err := v.Put(vaultCtx(softID, soft), f.db, validVault("wrapped")); err != nil {
		t.Fatal(err)
	}
	softDelete(t, f.db, softID)
	if n := vaultRows(t, f.db, softID); n != 1 {
		t.Errorf("a soft delete removed the vault row (%d rows) — the two deletes have opposite "+
			"meanings and this one is recoverable", n)
	}
}

// TestDBE2EEParamColumnsNotNull @notice The five parameter columns reject null; the three blob
// columns do not.
//
// @dev A null in any of the five scans into a Go zero value on the way to the client, which then
// derives with memory = 0 and produces a key nothing can reproduce. The blob columns are nullable
// by design — "null until enrolment" — so asserting the boundary rather than "everything is not
// null" is what makes this a schema case and not a wish.
//
// Covers: E2EE-SCH-005
func TestDBE2EEParamColumnsNotNull(t *testing.T) {
	f := newAuthnFixture(t)

	for _, col := range []string{"kdf", "salt", "memory", "iterations", "parallelism"} {
		id := f.createPasswordUser(t, "null-"+col+"@example.test", "the original password")
		cols := directVaultColumns(id)
		cols[col] = nil
		if err := putVaultDirect(f.db, cols); err == nil {
			t.Errorf("%s accepted null — a client reading it derives with a zero and produces a key "+
				"nothing can reproduce", col)
		}
	}

	id := f.createPasswordUser(t, "null-blob@example.test", "the original password")
	cols := directVaultColumns(id)
	cols["wrapped_key"] = nil
	if err := putVaultDirect(f.db, cols); err != nil {
		t.Errorf("wrapped_key is documented as null until enrolment and the schema refused it: %v", err)
	}
}

// TestDBE2EEPreEnrolmentRow @notice [UNSPECIFIED] A row with no wrapped key reads as a vault.
//
// @dev wrapped_key is nullable ("null until enrolment", per the migration) but Put refuses an empty
// key, so the state is unreachable through the API and reachable through SQL. Get then returns a
// non-nil *Vault with a nil WrappedKey, and a client that checks `vault != nil` imports a
// zero-length key.
//
// Recorded rather than judged: the nullable column is the enrolment-in-progress state the migration
// documents, and the gap is between that and what Get returns.
//
// Covers: E2EE-SCH-006
func TestDBE2EEPreEnrolmentRow(t *testing.T) {
	f, v := newVaultFixture(t)
	const addr = "preenrolment@example.test"
	id := f.createPasswordUser(t, addr, "the original password")

	cols := directVaultColumns(id)
	cols["wrapped_key"] = nil
	if err := putVaultDirect(f.db, cols); err != nil {
		t.Fatal(err)
	}

	got, err := v.Get(vaultCtx(id, addr), f.db)
	if err != nil {
		t.Fatalf("Get over a pre-enrolment row: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil for a row that exists — if absence now means the wrapped key and " +
			"not the row, this case records the new contract")
	}
	if len(got.WrappedKey) != 0 {
		t.Errorf("wrapped key = %q, want empty", got.WrappedKey)
	}

	// The API cannot produce this state, which is what keeps it a schema observation rather than a
	// live hazard.
	other := f.createPasswordUser(t, "preenrolment-api@example.test", "the original password")
	requireErrorCode(t,
		v.Put(vaultCtx(other, "preenrolment-api@example.test"), f.db,
			e2ee.Vault{RecoveryWrappedKey: []byte("recovery")}),
		kalerr.CodeInvalidInput)
}

// TestDBE2EENoExtraIndexes @notice The vault table carries no index beyond its primary key.
//
// @dev Gotcha 72: a blind index restores equality lookup and is an offline dictionary oracle on any
// low-entropy field. Nothing here needs one, and one added "for performance" would be the first
// step toward the thing the module exists to prevent.
//
// Read from the live catalogue rather than the migration text, so an index created anywhere else
// still appears.
//
// Covers: E2EE-SCH-008
func TestDBE2EENoExtraIndexes(t *testing.T) {
	db := testDB(t)
	var rows []struct{ Indexname string }
	if _, err := db.Query(&rows,
		`select indexname from pg_indexes where schemaname = ? and tablename = 'auth_e2ee_vaults'`,
		testSchema); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Indexname)
		}
		t.Fatalf("auth_e2ee_vaults carries %d indexes (%v), want only the primary key — any index over "+
			"a ciphertext column is an offline dictionary oracle", len(rows), names)
	}
	if !strings.Contains(rows[0].Indexname, "pkey") {
		t.Errorf("the one index is %q, which does not look like the primary key", rows[0].Indexname)
	}
}

// TestDBE2EEMigrationShape @notice The applied table has exactly the columns the module reads.
//
// @dev The text half of E2EE-SCH-007 is TestE2EEMigrationOnlyAdds; this is the half that needs the
// migration to have actually run. Both statements in sql.go scan positionally, so a column that
// quietly changed type or disappeared surfaces here rather than as a scan error in one flow.
//
// Covers: E2EE-SCH-007
func TestDBE2EEMigrationShape(t *testing.T) {
	db := testDB(t)
	var rows []struct {
		ColumnName string
		IsNullable string
	}
	if _, err := db.Query(&rows,
		`select column_name, is_nullable from information_schema.columns
		  where table_schema = ? and table_name = 'auth_e2ee_vaults' order by column_name`,
		testSchema); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"user_id": "NO", "kdf": "NO", "salt": "NO", "memory": "NO", "iterations": "NO",
		"parallelism": "NO", "wrapped_key": "YES", "recovery_wrapped_key": "YES",
		"wrapped_for": "YES", "key_version": "NO", "updated_at": "NO",
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.ColumnName] = r.IsNullable
	}
	for name, nullable := range want {
		if got[name] == "" {
			t.Errorf("auth_e2ee_vaults has no %s column", name)
			continue
		}
		if got[name] != nullable {
			t.Errorf("%s is_nullable = %s, want %s", name, got[name], nullable)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("auth_e2ee_vaults grew a %s column with no case describing it", name)
		}
	}
}
