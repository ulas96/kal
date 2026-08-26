package tests

import (
	"context"
	"testing"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/authz"
)

// TestDBScopedCRUD @notice The scoped crud four carry the ownership predicate on their own:
// another owner's rows are unreadable, undeletable and unwritable through them, and a caller's
// own query options cannot widen that back out.
//
// @dev These assert against the table rather than against the return value. A delete that
// reports false while the row quietly disappears, or an update that reports not-found after
// overwriting someone else's title, passes any test that only reads what the method returned —
// and that is the exact shape of the bug these methods exist to prevent.
//
// @param t the test handle
func TestDBScopedCRUD(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	auth, err := kal.New(newTestConfig(db))
	if err != nil {
		t.Fatal(err)
	}

	alice := createUser(t, db, "alice-scoped@example.com")
	bob := createUser(t, db, "bob-scoped@example.com")

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

	titleOf := func(t *testing.T, id string) string {
		t.Helper()
		var title string
		if _, err := db.QueryOne(pg.Scan(&title), `select title from docs where id = ?`, id); err != nil {
			t.Fatal(err)
		}
		return title
	}

	t.Run("List sees only the caller's rows", func(t *testing.T) {
		rows, err := auth.List[doc](aliceCtx, db, "owner_id")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ID != aliceDoc {
			t.Errorf("got %d rows, want only alice's", len(rows))
		}
	})

	t.Run("List for an anonymous caller sees nothing", func(t *testing.T) {
		rows, err := auth.List[doc](ctx, db, "owner_id")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("an anonymous caller read %d rows; the predicate failed open", len(rows))
		}
	})

	t.Run("Get of another owner's row is indistinguishable from absent", func(t *testing.T) {
		got, err := auth.Get[doc](aliceCtx, db, "owner_id", &doc{ID: bobDoc})
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Error("alice read bob's row")
		}
	})

	t.Run("Delete of another owner's row reports nothing and leaves the row", func(t *testing.T) {
		deleted, err := auth.Delete[doc](aliceCtx, db, "owner_id", &doc{ID: bobDoc})
		if err != nil {
			t.Fatal(err)
		}
		if deleted {
			t.Error("alice deleted bob's row")
		}
		var n int
		if _, err := db.QueryOne(pg.Scan(&n), `select count(*) from docs where id = ?`, bobDoc); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Error("bob's row is gone despite the delete reporting nothing")
		}
	})

	t.Run("Update of another owner's row leaves the title alone", func(t *testing.T) {
		_, err := auth.Update[doc](aliceCtx, db, "owner_id",
			&doc{ID: bobDoc, OwnerID: bob, Title: "alice was here"}, "doc")
		if err == nil {
			t.Error("alice updated bob's row")
		}
		if got := titleOf(t, bobDoc); got != "bob's" {
			t.Errorf("bob's title is %q; the update landed despite reporting an error", got)
		}
	})

	// The ordering property. Scope is applied before the caller's opts and go-pg ANDs successive
	// WHERE clauses, so an opt can narrow the result but never widen it. Append the predicate
	// last instead and this opt becomes a bypass — a caller-supplied Where that ORs another
	// owner's rows back in, which is the difference between an escape hatch and a hole.
	t.Run("a caller's own opt cannot widen the scope", func(t *testing.T) {
		rows, err := auth.List[doc](aliceCtx, db, "owner_id", func(q *orm.Query) *orm.Query {
			return q.WhereOr("owner_id = ?", bob)
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.OwnerID == bob {
				t.Fatal("a caller-supplied opt widened the scope to another owner's rows")
			}
		}
	})
}
