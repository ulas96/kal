package tests

import (
	"context"
	"testing"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/ulas96/luima"

	"github.com/ulas96/kal/authz"
)

// doc @notice A domain table standing in for whatever a consumer owns rows in.
type doc struct {
	tableName struct{} `pg:"docs"` //nolint:unused // go-pg reads this by reflection
	ID        string   `pg:"id,pk"`
	OwnerID   string   `pg:"owner_id"`
	Title     string   `pg:"title"`
}

// TestDBScope @notice Two owners, one table: a scoped read sees only your rows, and a scoped
// delete leaves someone else's row exactly where it was.
//
// @dev The delete assertion is the one that matters. Reporting "not found" while the row
// quietly disappears would pass a naive test that only checks the return value, so this checks
// the table afterwards.
//
// @param t the test handle
func TestDBScope(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	alice := createUser(t, db, "alice-scope@example.com")
	bob := createUser(t, db, "bob-scope@example.com")

	if _, err := db.Exec(`create table docs (
		id       uuid primary key default gen_random_uuid(),
		owner_id uuid not null references auth_users(id),
		title    text not null)`); err != nil {
		t.Fatal(err)
	}
	var aliceDoc, bobDoc string
	if _, err := db.QueryOne(pg.Scan(&aliceDoc),
		`insert into docs (owner_id, title) values (?, 'alice''s') returning id`, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueryOne(pg.Scan(&bobDoc),
		`insert into docs (owner_id, title) values (?, 'bob''s') returning id`, bob); err != nil {
		t.Fatal(err)
	}

	aliceCtx := authz.WithPrincipal(ctx, &authz.Principal{UserID: alice, SessionID: "s"})

	t.Run("a scoped list sees only your rows", func(t *testing.T) {
		rows, err := luima.List[doc](ctx, db, authz.Scope(aliceCtx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ID != aliceDoc {
			t.Errorf("list returned %d rows, want only alice's", len(rows))
		}
	})

	t.Run("a scoped delete of someone else's row reports nothing and changes nothing", func(t *testing.T) {
		deleted, err := luima.Delete(ctx, db, &doc{ID: bobDoc}, authz.Scope(aliceCtx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if deleted {
			t.Error("alice deleted bob's row")
		}
		// The return value is only half the property: the row must still be there.
		var n int
		if _, err := db.QueryOne(pg.Scan(&n), `select count(*) from docs where id = ?`, bobDoc); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Error("bob's row is gone despite the delete reporting nothing")
		}
	})

	t.Run("a scoped delete of your own row works", func(t *testing.T) {
		deleted, err := luima.Delete(ctx, db, &doc{ID: aliceDoc}, authz.Scope(aliceCtx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if !deleted {
			t.Error("alice could not delete her own row")
		}
	})

	t.Run("anonymous matches nothing", func(t *testing.T) {
		rows, err := luima.List[doc](ctx, db, authz.Scope(ctx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("an anonymous scope returned %d rows — it must fail closed", len(rows))
		}
	})

	t.Run("the bypass role is a no-op", func(t *testing.T) {
		adminCtx := authz.WithBypassRole(
			authz.WithPrincipal(ctx, &authz.Principal{UserID: alice, Roles: []string{"Admin"}}),
			"admin")
		rows, err := luima.List[doc](ctx, db, authz.Scope(adminCtx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ID != bobDoc {
			t.Errorf("bypass returned %d rows, want every remaining row", len(rows))
		}

		// Without the bypass role installed, the same principal is scoped normally.
		plainCtx := authz.WithPrincipal(ctx, &authz.Principal{UserID: alice, Roles: []string{"admin"}})
		rows, err = luima.List[doc](ctx, db, authz.Scope(plainCtx, "owner_id"))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("a role named admin bypassed without being configured as the bypass role")
		}
	})
}

// TestHasRole @notice Role matching is case-insensitive, and anonymous holds nothing. No
// database needed.
//
// @param t the test handle
func TestHasRole(t *testing.T) {
	ctx := authz.WithPrincipal(context.Background(), &authz.Principal{Roles: []string{"Editor"}})
	if !authz.HasRole(ctx, "editor") {
		t.Error(`HasRole("editor") = false for a principal holding "Editor"`)
	}
	if authz.HasRole(ctx, "admin") {
		t.Error(`HasRole("admin") = true`)
	}
	if authz.HasRole(context.Background(), "editor") {
		t.Error("an anonymous caller holds a role")
	}
}

// TestDBRoles @notice Grant, revoke and read-back, and the property that matters most: a
// revoked role is gone from the caller's next request, not from their next login.
//
// @param t the test handle
func TestDBRoles(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	r, err := authz.NewRoles(testSchema)
	if err != nil {
		t.Fatal(err)
	}
	uid := createUser(t, db, "roleholder@example.com")

	if err := r.Ensure(ctx, db, "admin", "full access"); err != nil {
		t.Fatal(err)
	}
	if err := r.Ensure(ctx, db, "admin", "full access, again"); err != nil {
		t.Errorf("Ensure is not idempotent: %v", err)
	}
	if err := r.Grant(ctx, db, uid, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.Grant(ctx, db, uid, "admin"); err != nil {
		t.Errorf("Grant is not idempotent: %v", err)
	}

	got, err := r.ForUser(ctx, db, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "admin" {
		t.Errorf("ForUser = %v, want [admin]", got)
	}

	if err := r.Grant(ctx, db, uid, "no-such-role"); err == nil {
		t.Error("granting an undefined role succeeded — the foreign key is the typo check")
	}

	if err := r.Revoke(ctx, db, uid, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(ctx, db, uid, "admin"); err != nil {
		t.Errorf("Revoke is not idempotent: %v", err)
	}
	got, err = r.ForUser(ctx, db, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("ForUser after revoke = %v, want empty", got)
	}
}

// TestDBRLS @notice The third layer: policies see the caller through transaction-local GUCs,
// and the setting does not survive the transaction.
//
// @dev The setup here is the test. Two roles bypass RLS entirely and both are easy to be
// running as by accident:
//
//   - The table owner, unless ALTER TABLE … FORCE ROW LEVEL SECURITY. Most migrations connect
//     as the owner, which is the single most common way an RLS deployment is quietly broken.
//   - A superuser or any role with BYPASSRLS — and CI's postgres user is a superuser. FORCE
//     does not help here; measured, a superuser sees every row through a policy that excludes
//     them, with no error.
//
// So the assertions run after SET LOCAL ROLE onto an unprivileged role, and the guard subtest
// proves that role really is unprivileged. Without both, this whole test would pass while
// proving nothing about RLS at all.
//
// @param t the test handle
func TestDBRLS(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	alice := createUser(t, db, "alice-rls@example.com")
	bob := createUser(t, db, "bob-rls@example.com")

	if _, err := db.Exec(`create table notes (
		id       uuid primary key default gen_random_uuid(),
		owner_id uuid not null,
		body     text not null)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into notes (owner_id, body) values (?, 'alice'), (?, 'bob')`, alice, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		alter table notes enable row level security;
		alter table notes force row level security;
		create policy notes_owner on notes
		  using (owner_id = nullif(current_setting('app.user_id', true), '')::uuid)`); err != nil {
		t.Fatal(err)
	}

	// An unprivileged role to run the policy checks as. NOLOGIN: it is only ever reached
	// through SET LOCAL ROLE, so it needs no password and cannot be connected to.
	const role = "kal_rls_test"
	if _, err := db.Exec(`do $$ begin
		if not exists (select 1 from pg_roles where rolname = '` + role + `') then
			create role ` + role + ` nologin;
		end if;
	end $$`); err != nil {
		// A restricted DATABASE_URL cannot create roles. Skipping is honest — but say exactly
		// what is going unproven, because a silent skip here would hide the whole layer.
		t.Skipf("cannot create an unprivileged role, so RLS enforcement cannot be proven: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`drop owned by ` + role + `; drop role if exists ` + role)
	})
	if _, err := db.Exec(`grant usage on schema ? to `+role+`;
		grant select, insert on notes to `+role, pg.Ident(testSchema)); err != nil {
		t.Fatal(err)
	}

	// asRole @notice Runs fn through WithRLS with the connection switched to the unprivileged
	// role first, which is what makes the policy apply at all.
	asRole := func(c context.Context, fn func(orm.DB) error) error {
		return authz.WithRLS(c, db, func(tx orm.DB) error {
			if _, err := tx.ExecContext(ctx, `set local role `+role); err != nil {
				return err
			}
			return fn(tx)
		})
	}

	aliceCtx := authz.WithPrincipal(ctx, &authz.Principal{UserID: alice, Roles: []string{"editor"}})

	t.Run("the test role does not bypass RLS", func(t *testing.T) {
		var super, bypass bool
		var current string
		if err := asRole(aliceCtx, func(tx orm.DB) error {
			_, err := tx.QueryOneContext(ctx, pg.Scan(&current, &super, &bypass),
				`select current_user, rolsuper, rolbypassrls from pg_roles where rolname = current_user`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if current != role {
			t.Fatalf("current_user = %q, want %q — the role switch did not happen", current, role)
		}
		if super || bypass {
			t.Fatalf("the test role is superuser=%v bypassrls=%v; every assertion below would be vacuous", super, bypass)
		}
	})

	t.Run("the policy sees the caller", func(t *testing.T) {
		var bodies []string
		if err := asRole(aliceCtx, func(tx orm.DB) error {
			_, err := tx.QueryContext(ctx, &bodies, `select body from notes order by body`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(bodies) != 1 || bodies[0] != "alice" {
			t.Errorf("rows = %v, want only alice's — the policy did not see app.user_id", bodies)
		}
	})

	t.Run("both GUCs are set", func(t *testing.T) {
		var user, roles string
		if err := asRole(aliceCtx, func(tx orm.DB) error {
			_, err := tx.QueryOneContext(ctx, pg.Scan(&user, &roles),
				`select current_setting('app.user_id', true), current_setting('app.roles', true)`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if user != alice || roles != "editor" {
			t.Errorf("GUCs = %q, %q, want %q, %q", user, roles, alice, "editor")
		}
	})

	t.Run("an anonymous caller sees nothing", func(t *testing.T) {
		var n int
		if err := asRole(ctx, func(tx orm.DB) error {
			_, err := tx.QueryOneContext(ctx, pg.Scan(&n), `select count(*) from notes`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("an anonymous caller saw %d rows — the policy fails open on an empty setting", n)
		}
	})

	t.Run("the setting is transaction-local", func(t *testing.T) {
		if err := asRole(aliceCtx, func(orm.DB) error { return nil }); err != nil {
			t.Fatal(err)
		}
		// A plain session-scoped SET would leak onto the pooled connection and this would come
		// back as alice's id — a cross-tenant leak that only shows up under concurrency.
		var leaked string
		if _, err := db.QueryOne(pg.Scan(&leaked), `select current_setting('app.user_id', true)`); err != nil {
			t.Fatal(err)
		}
		if leaked != "" {
			t.Errorf("app.user_id = %q after the transaction — the setting outlived it", leaked)
		}
	})

	t.Run("an error rolls the transaction back", func(t *testing.T) {
		sentinel := context.Canceled
		err := authz.WithRLS(aliceCtx, db, func(tx orm.DB) error {
			if _, err := tx.ExecContext(ctx, `insert into notes (owner_id, body) values (?, 'ghost')`, alice); err != nil {
				return err
			}
			return sentinel
		})
		if err == nil {
			t.Fatal("WithRLS swallowed the callback's error")
		}
		var n int
		if _, err := db.QueryOne(pg.Scan(&n), `select count(*) from notes where body = 'ghost'`); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Error("the failed transaction committed its insert")
		}
	})
}
