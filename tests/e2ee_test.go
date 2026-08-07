package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/e2ee"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/migrations"
)

// Every case in this file runs without a database, and none of them may be named TestDB* —
// TestDB* skips when DATABASE_URL is unset and a skip still reports ok, which would make the
// import allowlist, the auth-secret shape and the documented refusals read green on a machine
// with no Postgres (docs/e2ee-test-cases.md P-1).

// e2eeAllowedImports @notice Everything the e2ee package may import, directly.
//
// @dev An allowlist rather than the denylist the design called for. A denylist over `go list
// -deps` cannot work: e2ee takes orm.DB in every signature, go-pg reaches crypto/tls, and
// crypto/tls pulls crypto/aes, crypto/cipher and crypto/hkdf into the transitive closure of every
// package in this module — `go list -deps ./authz` already prints all three. A test that fails on
// day one gets deleted, and this is the one test that must not be.
//
// The allowlist is also strictly stronger: it fails on a new kal package doing the crypto on
// e2ee's behalf, which a fixed list of forbidden standard-library paths would wave through.
var e2eeAllowedImports = map[string]bool{
	"context":                       true,
	"crypto/hmac":                   true,
	"crypto/sha256":                 true,
	"encoding/base64":               true,
	"errors":                        true,
	"fmt":                           true,
	"regexp":                        true,
	"strings":                       true,
	"github.com/go-pg/pg/v10":       true,
	"github.com/go-pg/pg/v10/orm":   true,
	"github.com/go-pg/pg/v10/types": true,
	"github.com/ulas96/kal/authz":   true,
	"github.com/ulas96/kal/kalerr":  true,
	"github.com/ulas96/kal/session": true,
}

// unlistedImports @notice The entries of imports the allowlist does not carry, sorted.
//
// @dev A function rather than a loop inside the test, so the gate itself can be exercised against
// an import list this module does not have. Without that, the only evidence the check works is
// that it currently passes — which is also what a check that can never fail looks like.
func unlistedImports(imports []string, allow map[string]bool) []string {
	var out []string
	for _, imp := range imports {
		if !allow[imp] {
			out = append(out, imp)
		}
	}
	sort.Strings(out)
	return out
}

// goListPackages @notice `go list` over one package, split into lines.
//
// ponytail: os/exec on go list — the alternative is x/tools/go/packages for a one-line question
func goListPackages(t *testing.T, format, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-f", format, pkg).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}

// TestE2EEImportGraph @notice The e2ee package imports no AEAD and no password KDF.
//
// @dev The test the whole premise rests on. If kal can decrypt, kal is not doing client-side
// encryption — it is doing server-side encryption with extra ceremony, sold under the same word.
// The rule is not enforceable by review, because the failing version arrives looking like a
// helpful convenience method. When someone later asks for e2ee.Decrypt "just for the admin tool",
// this is the answer. Every other test in this file can be rewritten around; this one cannot.
//
// The last two subtests are why the allowlist has the shape it has: the gate has to fire on a
// package added inside this module, and a denylist over the dependency closure would be red on the
// day it was written. The full E2EE-ISO-002 procedure — add a package importing crypto/aes, import
// it from e2ee, run, revert — is mutation M-30 and stays manual; what is automated here is the
// gate that mutation exercises.
//
// Covers: E2EE-ISO-001, E2EE-ISO-002
func TestE2EEImportGraph(t *testing.T) {
	direct := goListPackages(t, `{{join .Imports "\n"}}`, "github.com/ulas96/kal/e2ee")
	if len(direct) == 0 {
		t.Fatal("go list returned no imports for e2ee — the gate would pass over an empty set")
	}

	t.Run("every direct import is on the allowlist", func(t *testing.T) {
		for _, imp := range unlistedImports(direct, e2eeAllowedImports) {
			t.Errorf("e2ee imports %q, which is not on the allowlist — if this is deliberate, say "+
				"in the commit message why the package that must not be able to decrypt needs it", imp)
		}
	})

	// The negative variant E2EE-ISO-001(a) asks for: the gate must key on what is imported, not on
	// how long the list is. A check that compared lengths would pass the arm above and wave through
	// a swap of one import for another.
	t.Run("the gate is the import list, not the allowlist length", func(t *testing.T) {
		wider := map[string]bool{"crypto/aes": true}
		for k, v := range e2eeAllowedImports {
			wider[k] = v
		}
		if got := unlistedImports(direct, wider); len(got) != 0 {
			t.Errorf("an allowlist entry for an unimported package changed the verdict: %v", got)
		}
		narrower := map[string]bool{}
		for k, v := range e2eeAllowedImports {
			narrower[k] = v
		}
		delete(narrower, "crypto/hmac")
		if got := unlistedImports(direct, narrower); len(got) != 1 || got[0] != "crypto/hmac" {
			t.Errorf("removing an allowlist entry for an imported package reported %v, want [crypto/hmac] — "+
				"the check does not actually look at the imports", got)
		}
	})

	// The obvious workaround: a new package under this module that does the crypto on e2ee's
	// behalf. A denylist of standard-library paths waves it through; the allowlist names it.
	t.Run("crypto done on e2ee's behalf is named", func(t *testing.T) {
		synthetic := append(append([]string{}, direct...),
			"github.com/ulas96/kal/internal/vaultcrypto", "crypto/aes")
		got := unlistedImports(synthetic, e2eeAllowedImports)
		want := []string{"crypto/aes", "github.com/ulas96/kal/internal/vaultcrypto"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("unlisted = %v, want %v — a helper package imported by e2ee must not pass", got, want)
		}
	})

	// E2EE-ISO-001(b), asserted rather than believed: the denylist that will be proposed instead of
	// this allowlist is red on day one, and a test that is red on day one gets deleted.
	t.Run("a denylist over the dependency closure cannot work", func(t *testing.T) {
		deps := goListPackages(t, `{{join .Deps "\n"}}`, "github.com/ulas96/kal/e2ee")
		present := map[string]bool{}
		for _, d := range deps {
			present[d] = true
		}
		for _, forbidden := range []string{"crypto/aes", "crypto/cipher", "crypto/hkdf"} {
			if !present[forbidden] {
				t.Errorf("%s is no longer in e2ee's dependency closure — the reason this test is an "+
					"allowlist over direct imports may have gone away; check before changing the shape",
					forbidden)
			}
		}
	})
}

// exportedFuncsIn @notice The exported package-level functions declared in the given .go files,
// mapped to the source text of each declaration.
//
// @dev Methods are keyed as "(Recv).Name" so a widening of the surface through a method is visible
// to the same set comparison.
func exportedFuncsIn(t *testing.T, files []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(fset, name, raw, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil {
				key = "(" + nodeText(fset, raw, fn.Recv.List[0].Type) + ")." + fn.Name.Name
			}
			out[key] = string(raw[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
		}
	}
	return out
}

// nodeText @notice The source text of one AST node, for naming a method's receiver.
func nodeText(fset *token.FileSet, raw []byte, node ast.Node) string {
	return string(raw[fset.Position(node.Pos()).Offset:fset.Position(node.End()).Offset])
}

// sortedKeys @notice The keys of m, sorted, for a set comparison a diff can be read from.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestE2EEExportedSurface @notice No exported symbol can return a plaintext or a key, and the root
// shim does not widen the surface it forwards.
//
// @dev The import allowlist stops the crypto; it does not stop a method that takes a password and
// forwards it somewhere. The surface is the second half of the same control, and it is asserted as
// a whole set in both directions: "contains no method named Decrypt" is satisfied the moment the
// next one is called Reveal, and a rename that emptied the set would pass a presence-only check.
//
// Covers: E2EE-ISO-003, E2EE-ISO-004
func TestE2EEExportedSurface(t *testing.T) {
	root := repositoryRoot(t)

	t.Run("*Vaults offers exactly four methods", func(t *testing.T) {
		var got []string
		typ := reflect.TypeOf(&e2ee.Vaults{})
		for i := 0; i < typ.NumMethod(); i++ {
			got = append(got, typ.Method(i).Name)
		}
		sort.Strings(got)
		want := []string{"Discard", "Get", "Params", "Put"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("*e2ee.Vaults methods = %v, want exactly %v — an addition here is a new way for "+
				"bytes to leave, and a removal breaks a consumer silently", got, want)
		}
	})

	t.Run("the package exports three functions", func(t *testing.T) {
		files, err := filepath.Glob(filepath.Join(root, "e2ee", "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		got := sortedKeys(exportedFuncsIn(t, files))
		// The four *Vaults methods are asserted above through reflection; here the receiver-less
		// functions are the whole set.
		var pkgLevel []string
		for _, name := range got {
			if !strings.HasPrefix(name, "(") {
				pkgLevel = append(pkgLevel, name)
			}
		}
		want := []string{"NewRecoveryCode", "NewVaults", "ValidateAuthSecret"}
		if !reflect.DeepEqual(pkgLevel, want) {
			t.Errorf("e2ee package functions = %v, want exactly %v", pkgLevel, want)
		}
	})

	// The shim is hand-written, so a symbol can be added there that has no counterpart in e2ee and
	// no import-graph test over it. The set is closed deliberately: kal.New is on it because it
	// wires the vault, and anything else that reaches into e2ee has to be added here by hand, in a
	// diff a reviewer sees.
	t.Run("the shim adds nothing of its own", func(t *testing.T) {
		var touching []string
		for name, body := range exportedFuncsIn(t, []string{filepath.Join(root, "kal.go")}) {
			if strings.Contains(body, "e2ee.") {
				touching = append(touching, name)
			}
		}
		sort.Strings(touching)
		want := []string{"New", "NewRecoveryCode", "NewVaults", "ValidateAuthSecret"}
		if !reflect.DeepEqual(touching, want) {
			t.Errorf("kal.go functions reaching into e2ee = %v, want exactly %v — a kal.-only helper "+
				"that touches vault bytes has no test in e2ee's own group", touching, want)
		}
	})

	// The alias identity that keeps kal.Vault from becoming a hand-written copy is asserted at
	// compile time in kal_test.go:142-158, in both directions for all four types. It is not
	// repeated here: a runtime reflect.TypeOf comparison would be the weaker form of the same
	// check, and two copies of one assertion drift.
}

// TestE2EENewVaults @notice The constructor rejects everything that cannot have a safe default,
// and returns a nil service when it does.
//
// @dev The pepper is the one field with no default, deliberately: a pepper generated when missing
// differs per replica and per restart, so every salt in the deployment moves under the user's feet
// — logins keep working and every wrapped key becomes garbage. Behind a load balancer the vault
// opens on one pod and not the next.
//
// Covers: E2EE-CFG-001, E2EE-CFG-002, E2EE-CFG-003, E2EE-CFG-005
func TestE2EENewVaults(t *testing.T) {
	t.Run("the pepper floor is exactly 32 bytes", func(t *testing.T) {
		// 31 is the boundary that distinguishes a real bound from a nil guard; 33 and 64 are the
		// arm that catches a `len != 32` written in the other direction.
		for _, n := range []int{0, 1, 16, 31, 32, 33, 64} {
			v, err := e2ee.NewVaults(e2ee.Options{Pepper: bytes.Repeat([]byte{0x2b}, n)})
			switch {
			case n < 32 && err == nil:
				t.Errorf("a %d-byte pepper was accepted — it is a brute-forceable HMAC key, and "+
					"recovering it makes salt(email) computable offline", n)
			case n < 32 && v != nil:
				t.Errorf("a %d-byte pepper produced a usable *Vaults alongside the error — the caller "+
					"that ignores the error now has a service with a pepper nobody chose", n)
			case n >= 32 && err != nil:
				t.Errorf("a %d-byte pepper was rejected: %v", n, err)
			case n >= 32 && v == nil:
				t.Errorf("a %d-byte pepper returned no error and no service", n)
			}
		}
	})

	t.Run("an absent pepper is a hard error and a nil service", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts e2ee.Options
		}{
			{"the zero Options", e2ee.Options{}},
			{"an explicit nil", e2ee.Options{Pepper: nil}},
		} {
			v, err := e2ee.NewVaults(tc.opts)
			if err == nil {
				t.Errorf("%s: constructed — a generated pepper differs per replica and per restart", tc.name)
			}
			if v != nil {
				t.Errorf("%s: returned a usable *Vaults with the error", tc.name)
			}
		}
	})

	// [UNSPECIFIED] §17.10. The handout asked for *kalerr.Error on both branches; the pepper branch
	// is a bare errors.New three lines above a *kalerr.Error for the schema. Pinned as it is, so a
	// case written from the handout does not assert the wrong thing and get "fixed" by weakening it.
	t.Run("the two rejection branches do not carry the same error type", func(t *testing.T) {
		var typed *kalerr.Error
		_, pepperErr := e2ee.NewVaults(e2ee.Options{})
		if errors.As(pepperErr, &typed) {
			t.Errorf("the pepper branch now carries %s — today it is a bare errors.New (§17.10); if "+
				"this was deliberate, move the finding, do not delete the case", typed.Code)
		}
		_, schemaErr := e2ee.NewVaults(e2ee.Options{
			Pepper: bytes.Repeat([]byte{0x2b}, 32), Schema: "Not An Ident"})
		requireErrorCode(t, schemaErr, kalerr.CodeInvalidInput)
	})

	// The schema qualifier is the one string in this package that reaches SQL without a
	// placeholder: it is fmt.Sprintf'd into every statement in sql.go. The accepted names are
	// exercised against a live schema by TestDBE2EESchemaRenders — a regex that is right and an
	// AppendIdent that is wrong is still broken, and only executing the statements shows it.
	t.Run("the schema qualifier is validated, not quoted and hoped", func(t *testing.T) {
		pepper := bytes.Repeat([]byte{0x2b}, 32)
		for _, tc := range []struct {
			schema string
			ok     bool
		}{
			{testSchema, true},
			{"", true},
			{"public; drop table auth_users --", false},
			{"Kal", false},
			{"1kal", false},
			{"kal-test", false},
			{"kal.test", false},
			{`kal"`, false},
			{strings.Repeat("k", 200), true}, // in the class; length is Postgres's problem, not the regex's
		} {
			v, err := e2ee.NewVaults(e2ee.Options{Pepper: pepper, Schema: tc.schema})
			if tc.ok {
				if err != nil || v == nil {
					t.Errorf("schema %q was rejected: %v", tc.schema, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("schema %q was accepted — it is rendered into every statement unquoted by any "+
					"placeholder", tc.schema)
				continue
			}
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
			if v != nil {
				t.Errorf("schema %q returned a usable *Vaults with the error", tc.schema)
			}
		}
	})
}

// authSecretAlphabet @notice base64url, in index order, for constructing a non-canonical secret
// deliberately rather than by accident.
const authSecretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// randomAuthSecret @notice A correctly-derived auth secret and the 32 bytes behind it.
//
// @dev Random bytes rather than make([]byte, 32): the zero key encodes to 43 'A's, which exercises
// no alphabet edge at all and is exactly why the standard-alphabet case needs its own generator.
func randomAuthSecret(t *testing.T) (string, []byte) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return "kal1." + base64.RawURLEncoding.EncodeToString(raw), raw
}

// noncanonical @notice The same 43 characters with the final one's low bits set.
//
// @dev 43 base64url characters carry 258 bits for a 256-bit value, so the last character's two low
// bits must be zero — its alphabet index is a multiple of four. Adding one produces a string that a
// character-class regex accepts, a lenient decoder maps to the same 32 bytes, and a strict decode
// rejects. Picking the substitution deliberately is the point: most replacements also change the
// decoded bytes, and the case would then pass under a decoder that is not strict at all.
func noncanonical(t *testing.T, secret string) string {
	t.Helper()
	last := secret[len(secret)-1]
	idx := strings.IndexByte(authSecretAlphabet, last)
	if idx < 0 || idx%4 != 0 {
		t.Fatalf("final character %q of %q is not a canonical terminator", last, secret)
	}
	return secret[:len(secret)-1] + string(authSecretAlphabet[idx+1])
}

// TestValidateAuthSecret @notice Rejects anything that is not exactly a derived auth secret.
//
// @dev This is what stands between a deployment and silent data loss. Without it a client that
// sends the raw password — an un-updated mobile app, a curl in a runbook, a test fixture, a second
// frontend nobody remembered — logs in successfully, and the account is now hashed over a value
// the vault key was not derived from. Login works, the vault never opens, nothing errors and
// nothing logs.
//
// Covers: E2EE-SEC-001, E2EE-SEC-002, E2EE-SEC-003, E2EE-SEC-004, E2EE-SEC-005, E2EE-SEC-006,
// E2EE-SEC-007, E2EE-SEC-008
func TestValidateAuthSecret(t *testing.T) {
	valid := "kal1." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	// A secret that genuinely contains - and _, so the URL-safe alphabet is exercised rather than
	// assumed. A client using btoa without the substitution sends +/ for the same key.
	var urlSafe string
	var urlSafeRaw []byte
	for i := 0; i < 64 && urlSafe == ""; i++ {
		candidate, raw := randomAuthSecret(t)
		if strings.ContainsRune(candidate, '-') && strings.ContainsRune(candidate, '_') {
			urlSafe, urlSafeRaw = candidate, raw
		}
	}
	if urlSafe == "" {
		t.Fatal("could not draw a secret containing both - and _ in 64 attempts")
	}
	standardAlphabet := strings.NewReplacer("-", "+", "_", "/").Replace(urlSafe[5:])

	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"a plausible passphrase", "correct horse battery staple", false},
		{"a plausible password", "P@ssw0rd!2026", false},
		{"empty", "", false},
		{"the prefix alone", "kal1.", false},
		{"42 characters", valid[:len(valid)-1], false},
		{"44 characters", valid + "A", false},
		{"right shape, no prefix", valid[5:], false},
		{"wrong prefix", "kal2." + valid[5:], false},
		{"uppercase prefix", "KAL1." + valid[5:], false},
		// CutPrefix anchors at position zero. A Contains-shaped check would accept this, and the
		// version would be decorative the first time it mattered.
		{"a valid secret with something in front", "x" + valid, false},
		{"a valid secret with a leading space", " " + valid, false},
		{"standard base64 alphabet", "kal1." + strings.Repeat("+", 43), false},
		{"a real secret with +/ for -_", "kal1." + standardAlphabet, false},
		// 43 base64url characters carry 258 bits for a 256-bit value, so the last character's two
		// low bits must be zero. A character-class regex accepts this; a strict decode does not.
		{"non-canonical trailing bits", valid[:len(valid)-1] + "B", false},
		{"non-canonical trailing bits, random key", noncanonical(t, urlSafe), false},
		// RawURLEncoding and URLEncoding are one identifier apart in every standard library. The
		// padded form decodes to the right 32 bytes under a tolerant parser, and accepting it gives
		// one key two wire forms — the account is hashed over whichever arrived first.
		{"padded base64", "kal1." + base64.URLEncoding.EncodeToString(urlSafeRaw), false},
		// A secret is not an email address: Params trims its argument deliberately (see
		// TestDBE2EENormalisesBothPaths) and this must not, or two strings become one credential.
		//
		// The four newline forms are the ones a strict decode alone lets through: encoding/base64
		// skips \r and \n wherever they appear, and Strict() governs padding and trailing bits only
		// (gotcha 78). Each is a distinct string reaching the password column and a distinct hash
		// over one key. A shell heredoc supplies the first for free.
		{"trailing newline", valid + "\n", false},
		{"trailing carriage return", valid + "\r", false},
		{"trailing CRLF", valid + "\r\n", false},
		{"leading newline", "\n" + valid, false},
		{"an embedded newline", valid[:20] + "\n" + valid[20:], false},
		{"leading tab", "\t" + valid, false},
		{"trailing space", valid + " ", false},
		{"the real thing", valid, true},
		{"the real thing, with - and _", urlSafe, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := kal.ValidateAuthSecret(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("rejected a valid auth secret: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted — an account hashed over this cannot open the vault derived beside it")
			}
			// The error class is what a consumer's presenter maps: a bare error becomes a 500
			// where this becomes the 400 the client can act on.
			requireErrorCode(t, err, kalerr.CodeInvalidInput)
		})
	}

	// The shape check and docs/e2ee-client.md are one contract in two files. If the check tightened
	// without the doc changing, every conforming client breaks at once with INVALID_INPUT and no
	// route forward — so the documented derivation is run end to end, repeatedly, with the alphabet
	// exercised by randomness rather than by a fixture that happens to avoid it.
	t.Run("a secret from the documented derivation is always accepted", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			secret, _ := randomAuthSecret(t)
			if err := kal.ValidateAuthSecret(secret); err != nil {
				t.Fatalf("draw %d: %q rejected: %v", i, secret, err)
			}
			if err := kal.ValidateAuthSecret(noncanonical(t, secret)); err == nil {
				t.Fatalf("draw %d: the non-canonical form of the same key was accepted", i)
			}
		}
	})
}

// TestE2EERecoveryCodeShape @notice A recovery code is 32 bytes of base64url, and a fresh one each
// time.
//
// @dev A short or predictable code is brute-forceable against a stolen database with no rate limit
// in front of it, because the verifier is the wrapped blob and the attacker has it. Uniqueness
// alone is satisfied by a counter, so the distribution arm runs beside it: 32 draws of 32 bytes
// cannot tell crypto/rand from an incrementing integer, and 1024 draws cost nothing.
//
// Covers: E2EE-RCV-001, E2EE-RCV-002
func TestE2EERecoveryCodeShape(t *testing.T) {
	const draws = 1024
	seen := map[string]bool{}
	histogram := [256]int{}
	total := 0
	for i := 0; i < draws; i++ {
		code, err := kal.NewRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		// Strict, not merely decodable: a padded or standard-alphabet code breaks a client that
		// decodes strictly, and that client is the reference one.
		raw, err := base64.RawURLEncoding.Strict().DecodeString(code)
		if err != nil || len(raw) != 32 {
			t.Fatalf("code %q is not 32 bytes of unpadded base64url: %v", code, err)
		}
		if seen[code] {
			t.Fatal("a recovery code repeated — it is the only route back into a reset vault")
		}
		seen[code] = true
		for _, b := range raw {
			histogram[b]++
			total++
		}
	}

	distinct, worst := 0, 0
	for _, n := range histogram {
		if n > 0 {
			distinct++
		}
		if n > worst {
			worst = n
		}
	}
	// Coarse on purpose: this is not a randomness test suite, it is the arm that catches a
	// generator returning a fixed value or a narrow range under some other code path.
	if distinct < 250 {
		t.Errorf("%d of 256 byte values appeared across %d bytes — the source is not uniform", distinct, total)
	}
	if worst > total/100 {
		t.Errorf("one byte value took %d of %d — the source is skewed", worst, total)
	}
}

// TestE2EEShimFunctions @notice The re-exported functions behave identically to the package's own,
// and the KDF names carry their exact wire values.
//
// @dev A wrapper that adds a convenience — trimming the secret, defaulting the pepper — is a
// security change in a file whose job is forwarding, and no test in e2ee's own group would see it.
// The constants are compared against the literals rather than against each other: kal.KDFArgon2id
// == e2ee.KDFArgon2id is true for any pair of equal wrong values, and these strings are a wire
// contract a second client compares against.
//
// Covers: E2EE-SHM-002, E2EE-SHM-003
func TestE2EEShimFunctions(t *testing.T) {
	valid, _ := randomAuthSecret(t)
	for _, in := range []string{
		"correct horse battery staple", "P@ssw0rd!2026", "", "kal1.", valid[:len(valid)-1],
		valid + "A", valid[5:], "kal2." + valid[5:], noncanonical(t, valid), valid,
	} {
		shim, own := kal.ValidateAuthSecret(in), e2ee.ValidateAuthSecret(in)
		if (shim == nil) != (own == nil) {
			t.Errorf("%q: kal.ValidateAuthSecret = %v, e2ee.ValidateAuthSecret = %v", in, shim, own)
			continue
		}
		if shim != nil && shim.Error() != own.Error() {
			t.Errorf("%q: messages diverged: %q vs %q", in, shim, own)
		}
	}

	shimVaults, shimErr := kal.NewVaults(kal.VaultOptions{})
	ownVaults, ownErr := e2ee.NewVaults(e2ee.Options{})
	if shimVaults != nil || ownVaults != nil {
		t.Error("a pepper-less NewVaults returned a service through one of the two entry points")
	}
	if shimErr == nil || ownErr == nil || shimErr.Error() != ownErr.Error() {
		t.Errorf("NewVaults errors diverged: %v vs %v", shimErr, ownErr)
	}

	if kal.KDFArgon2id != "argon2id" || e2ee.KDFArgon2id != "argon2id" {
		t.Errorf("argon2id wire value = %q/%q, want \"argon2id\"", kal.KDFArgon2id, e2ee.KDFArgon2id)
	}
	if kal.KDFPBKDF2 != "pbkdf2" || e2ee.KDFPBKDF2 != "pbkdf2" {
		t.Errorf("pbkdf2 wire value = %q/%q, want \"pbkdf2\"", kal.KDFPBKDF2, e2ee.KDFPBKDF2)
	}
	if kal.KDFArgon2id == kal.KDFPBKDF2 {
		t.Error("the two KDF names are the same string")
	}
}

// TestE2EEFingerprintIsOneExpression @notice The write and the staleness read derive the
// password-hash fingerprint from one Go constant.
//
// @dev Two copies that drift make every vault in the deployment read stale forever: a working
// login, a key the client is told not to trust, and no error anywhere. The symptom is
// indistinguishable from "everyone reset their password", which is not a hypothesis anyone tests.
//
// This is the structural half only. Two identical strings that are both wrong pass it, which is
// what TestDBE2EEStaleAfterReset's live arm is for — the pair is the case, and neither half should
// be deleted without the other.
//
// Covers: E2EE-STL-010
func TestE2EEFingerprintIsOneExpression(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "e2ee", "sql.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, raw, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	referenced := map[string]bool{}
	literals := 0
	for _, decl := range parsed.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			name := vs.Names[0].Name
			ast.Inspect(vs.Values[0], func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					if node.Name == "wrappedForFingerprint" {
						referenced[name] = true
					}
				case *ast.BasicLit:
					if strings.Contains(node.Value, "sha256(") {
						literals++
					}
				}
				return true
			})
		}
	}

	for _, stmt := range []string{"putVaultSQL", "vaultByUserSQL"} {
		if !referenced[stmt] {
			t.Errorf("%s does not reference wrappedForFingerprint — if the expression was inlined, the "+
				"two copies drift and every vault reads stale forever", stmt)
		}
	}
	if literals != 1 {
		t.Errorf("the sha256 fingerprint expression appears in %d string literals, want 1 (the const)", literals)
	}
}

// TestE2EEMigrationOnlyAdds @notice 0003_e2ee.sql creates its one table and alters no core table.
//
// @dev An `alter table auth_users` in a module migration couples the optional feature to the core
// schema, and a deployment that never enables Config.E2EE carries the change anyway. The column
// shape is asserted against a live database by TestDBE2EEMigrationShape, and every migration's
// ordering is already tests/migrations_test.go's job — neither is duplicated here.
//
// Covers: E2EE-SCH-007
func TestE2EEMigrationOnlyAdds(t *testing.T) {
	var name string
	for _, candidate := range migrations.Files() {
		if strings.HasPrefix(candidate, "0003_") {
			name = candidate
		}
	}
	if name != "0003_e2ee.sql" {
		t.Fatalf("third migration = %q, want 0003_e2ee.sql", name)
	}
	raw, err := migrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	if !strings.Contains(sql, "create table auth_e2ee_vaults") {
		t.Error("the migration does not create auth_e2ee_vaults — a text-only check would otherwise " +
			"pass against an empty file")
	}
	if strings.Contains(sql, "alter table") {
		t.Error("the e2ee migration alters a table; a deployment that never enables Config.E2EE would " +
			"carry the change anyway")
	}
}

// normalizeProse @notice One document, comparable: comment markers stripped, every run of
// whitespace collapsed to a single space, lowercased.
//
// @dev The live hazard in §14 is a false *fail*, not a false pass. README.md, e2ee/e2ee.go and
// docs/e2ee-client.md all hard-wrap at 100 columns, so every clause below is split across a line
// break today — a naive strings.Contains over the raw bytes fails on all three and the case gets
// deleted as broken within a week.
func normalizeProse(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString(strings.TrimPrefix(strings.TrimSpace(line), "//"))
		b.WriteString(" ")
	}
	return strings.ToLower(strings.Join(strings.Fields(b.String()), " "))
}

// gotchaHeadingRE @notice The register's entry headings in docs/gotchas.md.
var gotchaHeadingRE = regexp.MustCompile(`(?m)^\*\*([0-9]+) ·`)

// gotchaCitationRE @notice A citation of a register entry from code or from a test.
var gotchaCitationRE = regexp.MustCompile(`gotcha ([0-9]+)`)

// TestE2EEDocs @notice The refusals, the costs and the register numbers, where a deployment will
// read them.
//
// @dev Gotcha 64 is not testable as behaviour: nothing in this module can defend against the
// operator who serves the JavaScript, and the paragraph saying so is the whole mitigation. A
// consumer who deploys this believing otherwise has deployed the wrong control, and the failure
// mode is that they *stop* doing the thing that would have worked.
//
// Rewording these paragraphs is a deliberate decision, not a test failure to be silenced.
//
// Covers: E2EE-DOC-001, E2EE-DOC-002, E2EE-DOC-003, E2EE-DOC-004, E2EE-DOC-006
func TestE2EEDocs(t *testing.T) {
	readme := normalizeProse(readRepositoryFile(t, "README.md"))
	pkgdoc := normalizeProse(readRepositoryFile(t, "e2ee", "e2ee.go"))
	clientdoc := normalizeProse(readRepositoryFile(t, "docs", "e2ee-client.md"))
	changelog := normalizeProse(readRepositoryFile(t, "CHANGELOG.md"))

	t.Run("the refusal is in all three places", func(t *testing.T) {
		for _, doc := range []struct{ name, text string }{
			{"README.md", readme}, {"e2ee package doc", pkgdoc}, {"docs/e2ee-client.md", clientdoc},
		} {
			for _, clause := range []string{
				"does not protect against the server that serves the javascript",
				"anyone who tells you otherwise is selling something",
				// The positive claim is not optional: a document carrying only the refusal reads as
				// a reason not to use the feature, which is its own failure.
				"kal cannot read your data",
			} {
				if !strings.Contains(doc.text, clause) {
					t.Errorf("%s no longer carries %q", doc.name, clause)
				}
			}
		}
	})

	t.Run("the costs are stated before a deployment discovers them", func(t *testing.T) {
		for _, doc := range []struct{ name, text string }{
			// The client doc is the file a frontend author reads, and the README is not.
			{"README.md", readme}, {"docs/e2ee-client.md", clientdoc},
		} {
			for _, clause := range []string{
				"the password means losing the data",
				"cannot be indexed, sorted, filtered or full-text searched",
				"stop working, permanently",
				"no longer enforce a password policy",
			} {
				if !strings.Contains(doc.text, clause) {
					t.Errorf("%s no longer states %q", doc.name, clause)
				}
			}
		}
	})

	t.Run("the rollout requirement is where an upgrading consumer looks", func(t *testing.T) {
		const clause = "every client that touches the password field must be updated in the same release"
		for _, doc := range []struct{ name, text string }{
			{"CHANGELOG.md", changelog}, {"docs/e2ee-client.md", clientdoc},
		} {
			if !strings.Contains(doc.text, clause) {
				t.Errorf("%s does not state the rollout requirement — the shape check turns a missed "+
					"client into a login failure, which is the right failure and still a failure", doc.name)
			}
		}
	})

	// The numbers are cited from code comments and from tests/. Renumbering silently redirects
	// every citation, so density is asserted separately from the count: a new entry appended as 78
	// is growth and must not fail this case.
	t.Run("the gotcha register is dense and correctly sectioned", func(t *testing.T) {
		raw := readRepositoryFile(t, "docs", "gotchas.md")
		seen := map[int]bool{}
		max := 0
		for _, match := range gotchaHeadingRE.FindAllStringSubmatch(raw, -1) {
			n, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatal(err)
			}
			if seen[n] {
				t.Errorf("gotcha %d appears twice", n)
			}
			seen[n] = true
			if n > max {
				max = n
			}
		}
		if len(seen) != max {
			t.Errorf("%d entries with a maximum of %d — the sequence has a gap, and every citation of a "+
				"number past it now points somewhere else", len(seen), max)
		}
		if max < 77 {
			t.Errorf("the register stops at %d; entries are never renumbered and never removed", max)
		}

		section := strings.Index(raw, "## Client-side encryption")
		if section < 0 {
			t.Fatal("docs/gotchas.md has no Client-side encryption section")
		}
		for n := 64; n <= 77; n++ {
			at := strings.Index(raw, fmt.Sprintf("\n**%d · ", n))
			if at < 0 {
				t.Errorf("gotcha %d is missing", n)
				continue
			}
			if at < section {
				t.Errorf("gotcha %d moved out of the client-side encryption section", n)
			}
		}
	})

	t.Run("every gotcha cited from e2ee resolves", func(t *testing.T) {
		raw := readRepositoryFile(t, "docs", "gotchas.md")
		exists := map[string]bool{}
		for _, match := range gotchaHeadingRE.FindAllStringSubmatch(raw, -1) {
			exists[match[1]] = true
		}

		var sources []string
		for _, pattern := range []string{
			filepath.Join(repositoryRoot(t), "e2ee", "*.go"),
			filepath.Join(repositoryRoot(t), "tests", "e2ee*_test.go"),
		} {
			found, err := filepath.Glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			sources = append(sources, found...)
		}

		citations := 0
		for _, name := range sources {
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, match := range gotchaCitationRE.FindAllStringSubmatch(string(body), -1) {
				citations++
				if !exists[match[1]] {
					t.Errorf("%s cites gotcha %s, which is not in the register", filepath.Base(name), match[1])
				}
			}
		}
		// An empty match set passes trivially, and a citation format change would produce one.
		if citations == 0 {
			t.Error("no gotcha citations found in e2ee or its tests — the extraction is broken")
		}
	})
}

// TestE2EEClientDocClaims @notice Every "kal validates X" sentence in docs/e2ee-client.md either
// resolves to a check in e2ee.go or is a recorded finding.
//
// @dev This is a review obligation with a checklist, not a code test — writing it as one is the
// false pass, because "the doc mentions validation" is not the same claim as "the code performs
// it". The checklist, in review order:
//
//	claim                                  | where it is performed
//	---------------------------------------|----------------------------------------------------
//	the "kal1." prefix                     | ValidateAuthSecret, asserted below
//	the auth secret's 32-byte length       | ValidateAuthSecret, asserted below
//	parallelism is pinned to 1             | withDefaults, the SQL literal, and the check
//	                                       | constraint — asserted by TestDBE2EEParallelismAlwaysOne
//	                                       | and TestDBE2EEParallelismConstraint
//	the blob's version and algorithm bytes | NOWHERE. §17.1: check() inspects len() only, and a
//	                                       | WrappedKey of []byte{0x00} is stored happily
//	                                       | (TestDBE2EEBlobBytesAreNotValidated).
//
// A second-client author reading that last sentence reasonably writes no version check of their
// own, and a 0x02 blob then reaches a client with no idea what it is holding. Either the code
// grows a two-byte check — three lines, and it does not require knowing how to decrypt — or the
// sentence changes. When either happens, this case and §17.1 move together.
//
// Covers: E2EE-DOC-005
func TestE2EEClientDocClaims(t *testing.T) {
	doc := normalizeProse(readRepositoryFile(t, "docs", "e2ee-client.md"))

	// The claims that are true, asserted through behaviour so the mapping is a mapping and not a
	// complaint.
	valid, raw := randomAuthSecret(t)
	if err := kal.ValidateAuthSecret(valid); err != nil {
		t.Errorf("the documented derivation is rejected: %v", err)
	}
	if err := kal.ValidateAuthSecret(base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Error("the doc says the kal1. prefix is required and it is not enforced")
	}
	if err := kal.ValidateAuthSecret("kal1." + base64.RawURLEncoding.EncodeToString(raw[:31])); err == nil {
		t.Error("the doc says the length is validated and it is not")
	}

	// The unbacked claim, pinned where it lives. If this fails, the doc was corrected — move §17.1,
	// do not delete the case.
	const claim = "kal validates the version byte, the algorithm byte and the length"
	if !strings.Contains(doc, claim) {
		t.Errorf("docs/e2ee-client.md no longer carries %q — if kal now validates those bytes, this "+
			"case and §17.1 both change; if the sentence was softened, say so in the diff", claim)
	}
}
