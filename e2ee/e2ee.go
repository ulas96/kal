// Package e2ee @notice Client-side encryption: the per-user KDF parameters a browser needs, and
// one opaque wrapped root key per user.
//
// @dev This package cannot decrypt anything, and that is the product. It imports no AEAD and no
// password KDF — the whole crypto surface here is an HMAC that derives a salt. If kal could
// decrypt, this would be server-side encryption with extra ceremony, which is a different thing
// sold under the same word. TestE2EEImportGraph is what holds the line, because the failing
// version always arrives looking like a helpful convenience method.
//
// The refusal this package carries: browser-delivered end-to-end encryption does not protect
// against the server that serves the JavaScript. An operator who wants the plaintext ships one
// line of JS to one user and has their master key on the next page load, and no amount of care in
// this Go package changes that. Anyone who tells you otherwise is selling something. The honest
// claim is that kal cannot read your data, and neither can anyone who reads your database.
//
// See docs/e2ee-client.md for the wire format and the derivation, and README.md for what enabling
// this costs a deployment.
package e2ee

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/go-pg/pg/v10/types"

	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/session"
)

// The client KDF names the `kdf` column may hold.
const (
	// KDFArgon2id @notice What every new enrolment gets. Not in WebCrypto; the reference client
	// takes it from hash-wasm.
	KDFArgon2id = "argon2id"
	// KDFPBKDF2 @notice The native browser fallback, kept openable rather than endorsed. It is
	// GPU-cheap, so a user on it should be re-wrapped to Argon2id on their next login.
	KDFPBKDF2 = "pbkdf2"
)

const (
	// authSecretPrefix @notice Versions the derivation, so a future scheme is distinguishable on
	// sight rather than by a decode that happens to fail.
	authSecretPrefix = "kal1."
	// authSecretBytes @notice HKDF's output width, and therefore the only accepted decode length.
	authSecretBytes = 32
	// authSecretChars @notice The encoded width of authSecretBytes, checked before the decode.
	//
	// @dev encoding/base64 skips \r and \n anywhere in its input, and Strict() does not turn that
	// off — it governs padding and trailing bits only. Without this length check "kal1.<43>\n",
	// "\n" in the middle, and \r\n at the end all decode to the same 32 bytes and are all accepted,
	// so one key reaches the password column in several forms and the account is hashed over
	// whichever arrived first (gotcha 78).
	authSecretChars = 43
	// saltDomain @notice Separates this HMAC from any other use of the same pepper.
	saltDomain     = "kal.e2ee.salt|"
	saltLen        = 16
	minPepperLen   = 32
	defaultMaxBlob = 8192
)

// identRe @notice What a schema qualifier may look like; same rule as the other packages.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Params @notice The client-side KDF parameters for one account, stored per user.
//
// @dev Stored rather than read from configuration at derive time: raise a default and every
// existing vault becomes unopenable, with a working login and no error anywhere (gotcha 67).
type Params struct {
	KDF        string
	Salt       []byte // 16 bytes, minted at first Put and never rotated
	Memory     uint32 // KiB; meaningless for pbkdf2, still recorded
	Iterations uint32
	// Parallelism @notice Always 1, on write and on read.
	//
	// @dev Argon2's p changes the output, so a browser that picks it from the thread pool derives
	// a different key on a laptop than on a phone and the second device reports a corrupt vault
	// (gotcha 66). The column carries a check constraint saying the same thing.
	Parallelism uint8
}

// withDefaults fills zero fields from d and pins Parallelism unconditionally.
func (p Params) withDefaults(d Params) Params {
	if p.KDF == "" {
		p.KDF = d.KDF
	}
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Iterations == 0 {
		p.Iterations = d.Iterations
	}
	p.Parallelism = 1
	return p
}

// Options @notice Configuration for NewVaults. Pepper is required; the zero value of everything
// else is the production posture.
type Options struct {
	// Pepper @notice Required, at least 32 bytes, and stable for the life of the deployment.
	//
	// @dev No default, and deliberately not generated when missing: a per-replica or per-restart
	// pepper moves the salt under the user's feet, and every wrapped key in the deployment becomes
	// garbage with a working login and no error. It is not protecting the salt — salts are not
	// secrets — it is what stops an attacker who knows the derivation, which is everyone, from
	// distinguishing the decoy salt of an unknown address from a real one.
	Pepper []byte

	// Default @notice Handed to new accounts and to addresses with no vault. Zero fields take
	// Argon2id at 64 MiB, 3 passes — roughly a second on a mid-range phone.
	Default Params

	// Floor @notice The minimum accepted on write. Zero fields take OWASP's m=19 MiB, t=2.
	//
	// @dev In Go rather than a check constraint, because a floor that is expected to rise over
	// time should not be a migration. Only `parallelism = 1` lives in the DB.
	Floor Params

	// MaxBlob @notice Byte ceiling on each stored blob. Zero means 8192.
	MaxBlob int

	// Schema @notice Optional Postgres schema holding the auth_* tables.
	Schema string

	// AllowNoRecovery @notice Lets a vault be written with no recovery wrapping. Off by default.
	//
	// @dev Named for the opt-out so that false is the safe posture. With recovery required, a user
	// who forgets their password has one route back; without it they have none, and the support
	// queue that produces cannot be answered by anyone, including the operator.
	AllowNoRecovery bool
}

// Vault @notice One user's wrapped root key, as kal stores it. Every byte field is opaque here.
type Vault struct {
	WrappedKey         []byte
	RecoveryWrappedKey []byte
	// Params @notice The client KDF this wrapping was produced under. Salt is ignored on write —
	// kal mints it, because a client-chosen salt would break the decoy indistinguishability that
	// Params depends on.
	Params Params
	// KeyVersion @notice The version this write expects to replace. Zero means "no row yet".
	KeyVersion int
	// Stale @notice The account's password moved since this key was wrapped, so the key derived
	// from the current password cannot open it.
	//
	// @dev Read-only; ignored on write. Without it the client receives a key it has no possible
	// way to open and fails somewhere far from the cause (gotcha 74).
	Stale bool
}

// Vaults @notice Reads and writes the one vault row per user, and answers the pre-auth parameter
// query every client makes before it can derive anything.
//
// @dev Carries no *pg.DB: every method takes orm.DB, so a consumer can put a vault write in the
// same transaction as the change that motivated it.
type Vaults struct {
	pepper          []byte
	def             Params
	floor           Params
	maxBlob         int
	allowNoRecovery bool
	sql             statements
}

// NewVaults @notice Validates opts, fills the parameter defaults and prepares the statements.
//
// @param opts    Pepper is required
// @return *Vaults ready for concurrent use
// @return error   a missing or short pepper, or an invalid schema name
func NewVaults(opts Options) (*Vaults, error) {
	if len(opts.Pepper) < minPepperLen {
		return nil, errors.New("e2ee: Options.Pepper is required and must be at least 32 bytes — there is no default, because a pepper generated when missing differs per replica and per restart, and the salt it produces would move under the user's feet")
	}
	v := &Vaults{
		pepper: opts.Pepper,
		// The client's cost, not the server's. Config.Argon2 is bounded by pod memory across
		// concurrent logins; this one is bounded by the slowest device a user owns, so the two are
		// separate numbers and neither may feed the other.
		def:             opts.Default.withDefaults(Params{KDF: KDFArgon2id, Memory: 65536, Iterations: 3}),
		floor:           opts.Floor.withDefaults(Params{KDF: KDFArgon2id, Memory: 19456, Iterations: 2}),
		maxBlob:         opts.MaxBlob,
		allowNoRecovery: opts.AllowNoRecovery,
	}
	if v.maxBlob <= 0 {
		v.maxBlob = defaultMaxBlob
	}
	prefix := ""
	if opts.Schema != "" {
		if !identRe.MatchString(opts.Schema) {
			return nil, &kalerr.Error{Code: kalerr.CodeInvalidInput,
				Message: "table schema must match ^[a-z_][a-z0-9_]*$"}
		}
		prefix = string(types.AppendIdent(nil, opts.Schema, 1)) + "."
	}
	v.sql = render(prefix)
	return v, nil
}

// salt @notice Derives an address's salt from the pepper, deterministically.
//
// @dev The one function that mints both the real salt at first Put and the decoy Params returns
// for an address with no vault. Deriving the decoy from the same function is what makes the two
// indistinguishable by construction rather than by care, and keeps them indistinguishable when
// someone later changes the derivation. A decoy generated fresh per call changes between two
// calls and the real salt does not, which is the enumeration oracle this replaces (gotcha 68).
func (v *Vaults) salt(email string) []byte {
	mac := hmac.New(sha256.New, v.pepper)
	mac.Write([]byte(saltDomain + email))
	return mac.Sum(nil)[:saltLen]
}

// Params @notice The KDF parameters for an address, whether or not it has an account.
//
// @dev Necessarily pre-auth: the client needs the salt before it can produce the auth secret, so
// it is asking about an account it has not authenticated to. Returning nil or an error for an
// unknown address is an account-enumeration oracle, so every address gets an answer. This also
// solves registration's chicken and egg — the client derives before the account exists, asks, and
// keeps what it gets — which is why authn.Register needs no knowledge of this package.
//
// Do not rate-limit this through auth_login_attempts: that table is the login backoff, and
// feeding it from an unauthenticated endpoint lets anyone lock any account out by repeatedly
// asking for its salt (gotcha 69). Rate-limit at the edge.
//
// @param email the address to derive for; normalised here
// @return Params the stored parameters, or the deterministic decoy plus Options.Default
// @return error  only a driver failure
func (v *Vaults) Params(ctx context.Context, db orm.DB, email string) (Params, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var stored Params
	_, err := db.QueryOneContext(ctx,
		pg.Scan(&stored.KDF, &stored.Salt, &stored.Memory, &stored.Iterations, &stored.Parallelism),
		v.sql.paramsByEmail, email)
	if errors.Is(err, pg.ErrNoRows) {
		p := v.def
		p.Salt = v.salt(email)
		return p, nil
	}
	if err != nil {
		return Params{}, err
	}
	return stored, nil
}

// Get @notice The caller's vault, or nil if they never enrolled.
//
// @dev Reads the user from the context principal, never from a parameter — an id parameter on a
// vault method is an IDOR waiting for one resolver to pass the wrong variable. Absence is not an
// error, the same way session.Lookup treats an unknown token.
//
// @return *Vault the wrapped keys and the staleness verdict; nil when there is no row
// @return error  UNAUTHENTICATED, or a driver failure
func (v *Vaults) Get(ctx context.Context, db orm.DB) (*Vault, error) {
	p, err := authz.Require(ctx)
	if err != nil {
		return nil, err
	}
	var out Vault
	_, err = db.QueryOneContext(ctx,
		pg.Scan(&out.WrappedKey, &out.RecoveryWrappedKey, &out.KeyVersion, &out.Stale,
			&out.Params.KDF, &out.Params.Salt, &out.Params.Memory, &out.Params.Iterations,
			&out.Params.Parallelism),
		v.sql.vaultByUser, p.UserID)
	if errors.Is(err, pg.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Put @notice Writes the caller's wrapped key, compare-and-swap on KeyVersion.
//
// @dev One statement, never a read followed by a write (gotcha 36's shape): two devices
// re-wrapping after a password change is a real race, not a theoretical one, and the loser has to
// learn that it lost rather than silently clobber the winner. Zero rows affected is CodeConflict.
//
// The stored salt is minted here on the first write and is never rotated afterwards, because a
// salt that moves when the email moves turns every wrapped key in the deployment into garbage,
// silently, with a working login. Rotating it is a re-wrap flow, not a maintenance task.
//
// @param vault the wrapped blobs, the parameters they were produced under, and the version this
//
//	write expects to replace; Params.Salt and Stale are ignored
//
// @return error UNAUTHENTICATED, INVALID_INPUT for a blob or parameter the policy rejects,
//
//	CONFLICT when another write got there first, or a driver failure
func (v *Vaults) Put(ctx context.Context, db orm.DB, vault Vault) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}
	if err := v.check(vault); err != nil {
		return err
	}
	params := vault.Params.withDefaults(v.def)
	var version int
	_, err = db.QueryOneContext(ctx, pg.Scan(&version), v.sql.putVault,
		params.KDF, v.salt(strings.ToLower(strings.TrimSpace(p.Email))),
		params.Memory, params.Iterations,
		vault.WrappedKey, vault.RecoveryWrappedKey, p.UserID, vault.KeyVersion)
	if errors.Is(err, pg.ErrNoRows) {
		return &kalerr.Error{Code: kalerr.CodeConflict,
			Message: "the vault changed since it was read; re-read it and try again", Internal: err}
	}
	return err
}

// check applies the policy that cannot live in the schema: the blob ceiling, the parameter floor
// and the recovery requirement.
func (v *Vaults) check(vault Vault) error {
	if len(vault.WrappedKey) == 0 {
		return invalidInput("a wrapped key is required")
	}
	// An authenticated caller with an unbounded bytea column has a free storage bucket
	// (gotcha 77).
	if len(vault.WrappedKey) > v.maxBlob || len(vault.RecoveryWrappedKey) > v.maxBlob {
		return invalidInput("wrapped key exceeds the configured maximum")
	}
	if !v.allowNoRecovery && len(vault.RecoveryWrappedKey) == 0 {
		return invalidInput("a recovery wrapping is required — without one, a forgotten password is unrecoverable data loss")
	}
	params := vault.Params.withDefaults(v.def)
	if params.KDF != KDFArgon2id && params.KDF != KDFPBKDF2 {
		return invalidInput("unknown client KDF")
	}
	if params.Memory < v.floor.Memory || params.Iterations < v.floor.Iterations {
		return invalidInput("client KDF parameters are below the configured floor")
	}
	return nil
}

// Discard @notice Deletes the caller's vault row.
//
// @dev For the user who reset their password, could not produce the old one and has given up.
// Deleting is theirs to ask for; kal does not do it on their behalf inside a password reset,
// because that would throw away a state they can still recover from.
//
// @return error UNAUTHENTICATED, or a driver failure
func (v *Vaults) Discard(ctx context.Context, db orm.DB) error {
	p, err := authz.Require(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, v.sql.deleteVault, p.UserID)
	return err
}

// ValidateAuthSecret @notice Accepts "kal1." followed by 43 base64url characters, and nothing else.
//
// @dev The single most likely way to break a deployment of this feature, and one shape check
// prevents all of it. Without it a client that sends the raw password — an un-updated mobile app,
// a curl in a runbook, a test fixture, a second frontend nobody remembered — logs in
// successfully, and the account is now hashed over a value the vault key was not derived from.
// Login works, the vault silently never opens, nothing errors and nothing logs (gotcha 65).
//
// The length check and the strict decode are one control in two halves, and neither covers the
// other. Strict decoding rejects the non-canonical encodings a character-class regex would wave
// through; the length check rejects the whitespace the decoder itself waves through, because
// encoding/base64 skips \r and \n wherever they appear and Strict() governs only padding and
// trailing bits (gotcha 78).
//
// @param s the value arriving in the field where the password used to go
// @return error a *kalerr.Error with CodeInvalidInput, or nil
func ValidateAuthSecret(s string) error {
	rest, ok := strings.CutPrefix(s, authSecretPrefix)
	if !ok {
		return invalidInput("expected a client-derived auth secret, not a password — see docs/e2ee-client.md")
	}
	if len(rest) != authSecretChars {
		return invalidInput("an auth secret is 32 bytes of unpadded base64url after \"kal1.\"")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(rest)
	if err != nil || len(raw) != authSecretBytes {
		return invalidInput("an auth secret is 32 bytes of unpadded base64url after \"kal1.\"")
	}
	return nil
}

// NewRecoveryCode @notice Mints a recovery code: 32 bytes from crypto/rand, base64url, shown once.
//
// @dev session.NewToken's shape, and its hash is deliberately discarded — there is nothing to
// store, because the wrapped key *is* the verifier. Nothing anywhere can check a recovery code
// except an attempt to unwrap with it, which is what keeps a stolen database from containing a
// second route into the vault.
//
// The code survives a password reset, because it wraps the vault key rather than being wrapped by
// the password. That is the intent: it is the only route back into a vault whose password moved.
//
// @return string the code, to show the user once and never again
// @return error  only a CSPRNG failure
func NewRecoveryCode() (string, error) {
	code, _, err := session.NewToken()
	return code, err
}

func invalidInput(message string) error {
	return &kalerr.Error{Code: kalerr.CodeInvalidInput, Message: message}
}
