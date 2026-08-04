package authz

import "fmt"

// Every SQL statement the package runs lives in this file (kal-wide rule; see session/sql.go
// for the reasoning). %[1]s is the optional schema qualifier rendered once by NewRoles.

func renderRoles(prefix string) roleStatements {
	return roleStatements{
		ensure:  fmt.Sprintf(ensureRoleSQL, prefix),
		grant:   fmt.Sprintf(grantRoleSQL, prefix),
		revoke:  fmt.Sprintf(revokeRoleSQL, prefix),
		forUser: fmt.Sprintf(rolesForUserSQL, prefix),
	}
}

// ensureRoleSQL @notice Idempotent role creation.
//
// @dev DO UPDATE rather than DO NOTHING so a changed description takes effect on the next
// startup — the row is a definition, not an event.
const ensureRoleSQL = `
insert into %[1]sauth_roles (name, description)
values (?, ?)
on conflict (name) do update set description = excluded.description`

// grantRoleSQL @notice Idempotent membership. The foreign key on role is what turns a typo
// into an error instead of a permission nobody has.
const grantRoleSQL = `
insert into %[1]sauth_user_roles (user_id, role)
values (?, ?)
on conflict (user_id, role) do nothing`

const revokeRoleSQL = `
delete from %[1]sauth_user_roles where user_id = ? and role = ?`

const rolesForUserSQL = `
select role from %[1]sauth_user_roles where user_id = ? order by role`
