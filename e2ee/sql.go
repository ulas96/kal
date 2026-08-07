package e2ee

import "fmt"

// Every SQL statement the package runs lives in this file (kal-wide rule; see session/sql.go for
// the reasoning). %[1]s is the optional schema qualifier rendered once by NewVaults.

type statements struct {
	paramsByEmail, vaultByUser, putVault, deleteVault string
}

func render(prefix string) statements {
	return statements{
		paramsByEmail: fmt.Sprintf(paramsByEmailSQL, prefix),
		vaultByUser:   fmt.Sprintf(vaultByUserSQL, prefix),
		putVault:      fmt.Sprintf(putVaultSQL, prefix),
		deleteVault:   fmt.Sprintf(deleteVaultSQL, prefix),
	}
}

// wrappedForFingerprint @notice The password-hash fingerprint stored beside a wrapped key, in one
// place because two statements need it.
//
// @dev Both the write and the staleness read compute it from this const. If the two expressions
// ever drift apart, every vault in the deployment reads as stale forever — a working login, a key
// the client is told not to trust, and no error anywhere.
//
// sha256() is built in since Postgres 11, so this keeps 0001_core.sql's no-extensions rule.
const wrappedForFingerprint = `sha256(convert_to(coalesce(u.password_hash, ''), 'UTF8'))`

// paramsByEmailSQL @notice The stored KDF parameters for an address.
//
// @dev No row is the ordinary case, not an error: Params answers for every address, and the
// caller supplies the deterministic decoy when this returns nothing. deleted_at gates here so a
// disabled account reads the same as an absent one.
const paramsByEmailSQL = `
select v.kdf, v.salt, v.memory, v.iterations, v.parallelism
  from %[1]sauth_e2ee_vaults v
  join %[1]sauth_users u on u.id = v.user_id
 where lower(u.email) = ? and u.deleted_at is null`

// vaultByUserSQL @notice The wrapped keys, the version, and whether the password moved under them.
//
// @dev The staleness comparison is a join rather than a column kal keeps in step, so a password
// reset makes it true without authn knowing this package exists — no hook, no callback, and no
// ordering requirement between two writes. IS DISTINCT FROM rather than <>, so a null
// fingerprint reads as stale instead of as null.
const vaultByUserSQL = `
select v.wrapped_key, v.recovery_wrapped_key, v.key_version,
       v.wrapped_for is distinct from ` + wrappedForFingerprint + `,
       v.kdf, v.salt, v.memory, v.iterations, v.parallelism
  from %[1]sauth_e2ee_vaults v
  join %[1]sauth_users u on u.id = v.user_id
 where v.user_id = ?`

// putVaultSQL @notice Inserts the first vault, or replaces a later one, compare-and-swap on
// key_version.
//
// @dev One statement. A read followed by a write leaves a window where two devices re-wrapping
// after the same password change both believe they won, and the second silently overwrites a key
// the first has already shown its user. Zero rows returned is the conflict.
//
// salt is absent from the update list on purpose: it is written once by the insert and never
// rotated. A salt that moves turns every wrapped key in the deployment into garbage, silently.
// kdf, memory and iterations do update, which is what makes moving a user off pbkdf2 a re-wrap on
// their next login rather than a migration.
//
// wrapped_for is computed here rather than passed in, so it is the hash as it stands at the
// instant of the write — computing it in Go would be a read-then-write racing a password change.
//
// The unqualified auth_e2ee_vaults in the ON CONFLICT clause is not a missing prefix: Postgres
// exposes the insert target there under its bare name whatever schema it lives in.
const putVaultSQL = `
insert into %[1]sauth_e2ee_vaults
       (user_id, kdf, salt, memory, iterations, parallelism,
        wrapped_key, recovery_wrapped_key, wrapped_for)
select u.id, ?, ?, ?, ?, 1, ?, ?, ` + wrappedForFingerprint + `
  from %[1]sauth_users u
 where u.id = ? and u.deleted_at is null
on conflict (user_id) do update
   set kdf                  = excluded.kdf,
       memory               = excluded.memory,
       iterations           = excluded.iterations,
       wrapped_key          = excluded.wrapped_key,
       recovery_wrapped_key = excluded.recovery_wrapped_key,
       wrapped_for          = excluded.wrapped_for,
       key_version          = auth_e2ee_vaults.key_version + 1,
       updated_at           = now()
 where auth_e2ee_vaults.key_version = ?
returning key_version`

const deleteVaultSQL = `
delete from %[1]sauth_e2ee_vaults where user_id = ?`
