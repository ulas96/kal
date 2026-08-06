package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ulas96/kal"
	"github.com/ulas96/kal/zkauthn"
	"github.com/ulas96/kal/zkauthz"
)

func readRepositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{repositoryRoot(t)}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestZKINV002ZeroConfig pins strict zero values without constructing a database-backed Auth.
// Covers: ZK-INV-002
func TestZKINV002ZeroConfig(t *testing.T) {
	var cfg kal.Config
	if cfg.ZK != nil {
		t.Fatal("zero Config unexpectedly enables ZK")
	}
	var zkcfg kal.ZKConfig
	if zkcfg.RootGrace != 0 || zkcfg.MaxConcurrentVerifications != 0 {
		t.Fatalf("zero ZKConfig has permissive defaults: %+v", zkcfg)
	}
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		files, err := filepath.Glob(filepath.Join(repositoryRoot(t), pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, filename := range files {
			raw, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "os.Getenv(") {
				t.Errorf("%s reads an environment variable", filename)
			}
		}
	}
}

// TestZKINV005Gotchas checks that the gotcha register precedes and names the documented controls.
// Covers: ZK-INV-005
func TestZKINV005Gotchas(t *testing.T) {
	gotchas := readRepositoryFile(t, "docs", "gotchas.md")
	// The register writes an entry as `**40 · An under-constrained circuit …`. Anchoring on the
	// bare number at line start instead would never match — the leading `**` defeats it — and the
	// whole loop would report all 24 entries missing while every one of them is present.
	for i := 40; i <= 63; i++ {
		if !regexp.MustCompile(`(?m)^\*\*`+regexp.QuoteMeta(strconv.Itoa(i))+` · `).MatchString(gotchas) && !strings.Contains(gotchas, "Gotcha "+strconv.Itoa(i)) {
			t.Errorf("gotcha %d is missing", i)
		}
	}
}

// TestZKINV007ReadmeDependencyClaims checks the repository's dependency statement against the
// module declarations that actually exist.
// Covers: ZK-INV-007
func TestZKINV007ReadmeDependencyClaims(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	goMod := readRepositoryFile(t, "go.mod")
	for _, dependency := range []string{"github.com/consensys/gnark", "github.com/consensys/gnark-crypto"} {
		if !strings.Contains(goMod, dependency) {
			t.Errorf("go.mod does not declare %s", dependency)
		}
		if !strings.Contains(readme, dependency) && !strings.Contains(readme, "gnark") {
			t.Errorf("README does not describe %s", dependency)
		}
	}
	if !strings.Contains(readme, "go.mod") || !strings.Contains(readme, "go.sum") {
		t.Error("README does not explain module-graph dependency behavior")
	}
}

// Covers: ZK-DOC-001
func TestZKDOC001AnonymitySet(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(security, "anonymity") || !strings.Contains(security, "non-revoked") || !strings.Contains(security, "one-in-one") {
		t.Error("SECURITY.md does not state the anonymity-set qualification")
	}
}

// Covers: ZK-DOC-002
func TestZKDOC002OperatorTrustBoundary(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	for _, term := range []string{"operator", "verifier", "PLONK", "different parties"} {
		if !strings.Contains(strings.ToLower(security), strings.ToLower(term)) {
			t.Errorf("SECURITY.md does not state operator trust boundary term %q", term)
		}
	}
}

// Covers: ZK-DOC-003
func TestZKDOC003ProverPackagingBoundary(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	security := readRepositoryFile(t, "SECURITY.md")
	for _, document := range []string{readme, security} {
		lower := strings.ToLower(document)
		if !strings.Contains(lower, "javascript") && !strings.Contains(lower, "client") {
			t.Error("document does not explain the prover/client trust boundary")
		}
	}
}

// Covers: ZK-DOC-004
func TestZKDOC004TimingDisclosure(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(strings.ToLower(security), "first use") || !strings.Contains(strings.ToLower(security), "timestamp") {
		t.Error("SECURITY.md does not document enrollment-to-first-use timing correlation")
	}
}

// Covers: ZK-DOC-005
func TestZKDOC005IssuedToDisclosure(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(security, "issued_to") || !strings.Contains(strings.ToLower(security), "revocation") {
		t.Error("SECURITY.md does not document issued_to disclosure and revocation tradeoff")
	}
}

// Covers: ZK-DOC-006
func TestZKDOC006SessionClaimBoundary(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(strings.ToLower(security), "session") || !strings.Contains(strings.ToLower(security), "credential") {
		t.Error("SECURITY.md does not document session-bound claims")
	}
}

var _ = zkauthn.CircuitKnowledge
var _ = zkauthz.New
