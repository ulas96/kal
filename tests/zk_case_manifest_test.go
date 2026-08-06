package tests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type zkCaseDisposition struct {
	kind   string
	reason string
}

// These are obligations the register itself says cannot be represented as an ordinary
// black-box test, or exact procedures that the exported surface cannot currently reach. They
// are deliberately not t.Skip calls: a skip would make an absent control read as a green one.
var zkNonAutomatedCases = map[string]zkCaseDisposition{
	"ZK-CIR-016": {"manual", "the register requires a named reviewer's sign-off on the flattened form"},
	"ZK-CIR-017": {"blocked", "no exported enrolment path accepts a caller-selected secret"},
	"ZK-HSH-002": {"partial", "zeros[32] and the service's complete precomputed zero table are not externally observable"},
	"ZK-HSH-003": {"partial", "the exported Secret type cannot represent the required 32-byte r and r+1 enrolment inputs"},
	"ZK-HSH-004": {"partial", "the package exposes no randomness injection seam for short-read and error propagation"},
	"ZK-CHL-010": {"partial", "there is no injectable database clock for a multi-TTL sustained-load run"},
	"ZK-ENR-005": {"partial", "secret, hash, and consumer response-write failures are not injectable through the exported API"},
	"ZK-KEY-004": {"partial", "the cross-toolchain and race-build comparison remains a manual environment gate"},
	"ZK-KEY-010": {"partial", "executing make audit is a standing gate and is forbidden by this test-implementation-only task"},
	"ZK-DOS-001": {"blocked", "no exported hook can hold a verification or observe semaphore occupancy deterministically"},
	"ZK-DOS-002": {"blocked", "the dummy verification cannot be held behind an occupied semaphore through the exported API"},
	"ZK-SQL-002": {"partial", "the Postgres 13/current non-superuser matrix requires external database environments"},
	"ZK-INV-004": {"partial", "the make test and make test-db executions remain standing gates"},
	"ZK-INV-006": {"partial", "a test cannot recursively prove that every named test is currently green"},
	"ZK-INV-009": {"manual", "make check at phase boundaries is a standing execution gate"},
	"ZK-SES-008": {"manual", "the expected anonymity-set calculation is an analytical deployment finding"},
	"ZK-E2E-006": {"partial", "catalog assertions are automated but the best-achievable-attribution conclusion requires audit sign-off"},
	"ZK-DOC-004": {"partial", "document text is automated but timestamp-granularity practicality is an analytical finding"},
}

// zkRoadmapCases are documented obligations with no test yet, each carrying the severity the
// register assigned it. They are not dispositions: nothing here is unreachable or analytical, and
// every entry is work that should be done. The bucket exists so the gap is counted rather than
// silent — deleting this test would make 78 unmet obligations invisible, and a t.Skip would make
// them read green.
//
// The count below is pinned deliberately. It can only fall by writing a test and moving an id out
// of this map, and it cannot rise without an explicit edit that a reviewer will see.
//
// Dated 2026-08-06. docs/vulnurability-test-cases.md §26 carries the same list in review order.
var zkRoadmapCases = map[string]zkCaseDisposition{
	"ZK-AUZ-004": {"critical", "AssertAuthCoverage still demands annotation on zk-gated fields"},
	"ZK-AUZ-005": {"critical", "The proven-claim set is loaded once per request"},
	"ZK-AUZ-006": {"essential", "Claims do not leak across requests"},
	"ZK-AUZ-007": {"essential", "An unknown claim denies"},
	"ZK-AUZ-008": {"critical", "An anonymous principal never satisfies proves:"},
	"ZK-AUZ-009": {"essential", "An empty proves: list has a defined meaning"},
	"ZK-AUZ-010": {"essential", "Claims bind to the session, and that property is stated"},
	"ZK-AUZ-011": {"essential", "A one-shot claim used as a session claim behaves predictably"},
	"ZK-AUZ-012": {"essential", "New mutations are in defaultSensitiveFields"},
	"ZK-AUZ-013": {"essential", "Claim names are opaque, with no expression syntax"},
	"ZK-CHL-002": {"critical", "A re-randomised proof does not replay"},
	"ZK-CHL-003": {"critical", "The burn is atomic"},
	"ZK-CHL-005": {"essential", "Expiry is enforced"},
	"ZK-CHL-006": {"essential", "Issuance deletes expired rows in the same statement"},
	"ZK-CHL-007": {"essential", "Challenges are unpredictable"},
	"ZK-CHL-008": {"essential", "A Membership challenge needs no session; a Knowledge challenge requires one"},
	"ZK-CHL-009": {"essential", "A challenge is not transferable between users or sessions"},
	"ZK-CIR-004": {"critical", "The adversarial witness generator"},
	"ZK-CIR-005": {"critical", "Path[0] binds to the prover's own secret"},
	"ZK-CIR-006": {"critical", "Range check precedes the comparison"},
	"ZK-CIR-007": {"critical", "The Merkle root is recomputed, not accepted"},
	"ZK-CIR-008": {"critical", "The nullifier is constrained to the secret and audience"},
	"ZK-CIR-009": {"critical", "Domain separation between leaf, nullifier and empty leaf"},
	"ZK-CIR-010": {"essential", "Index is bit-constrained and within the tree"},
	"ZK-CIR-013": {"essential", "Over-constraining at every boundary"},
	"ZK-CIR-014": {"essential", "CheckCircuit with valid and invalid assignments"},
	"ZK-DOS-003": {"critical", "The proof blob is length-checked before deserialization"},
	"ZK-DOS-004": {"essential", "The challenge endpoint is not a write amplifier"},
	"ZK-DOS-005": {"good-to-have", "Server-side proving, if it exists, has its own smaller bound"},
	"ZK-DOS-006": {"good-to-have", "The bound's ceiling is documented as per-replica"},
	"ZK-ENR-001": {"critical", "Membership enrolment is not self-service"},
	"ZK-ENR-002": {"critical", "Knowledge enrolment binds to the session's user"},
	"ZK-ENR-004": {"critical", "The attribute is set by the operator, never by the enrollee"},
	"ZK-ENR-006": {"essential", "Revocation names a person and revokes one leaf"},
	"ZK-HSH-005": {"critical", "The secret is returned exactly once and never stored"},
	"ZK-INP-002": {"critical", "Commitment comes from the session's user"},
	"ZK-INP-005": {"essential", "The prover names exactly three things"},
	"ZK-INP-006": {"essential", "Structurally invalid inputs fail before anything expensive"},
	"ZK-INV-008": {"good-to-have", "CHANGELOG.md carries an [Unreleased] entry per phase"},
	"ZK-KEY-001": {"critical", "No proving or verifying key is in the repository"},
	"ZK-KEY-005": {"critical", "ReadFrom, never UnsafeReadFrom"},
	"ZK-KEY-007": {"critical", "The ceremony is not deterministic"},
	"ZK-KEY-008": {"essential", "The proving key is not required by the verifier"},
	"ZK-KEY-009": {"good-to-have", "Constraint counts and prove/verify cost are measured and pinned"},
	"ZK-NUL-003": {"critical", "The primary key is the nullifier alone"},
	"ZK-NUL-004": {"critical", "Cross-audience unlinkability"},
	"ZK-NUL-005": {"essential", "Recurring and one-shot rows have disjoint shapes"},
	"ZK-NUL-006": {"essential", "The claim kind is constrained to two values"},
	"ZK-NUL-007": {"good-to-have", "An epoch in the audience gives per-epoch rate limiting"},
	"ZK-NUL-008": {"essential", "A proof does not cross deployments"},
	"ZK-NUL-009": {"essential", "A nullifier from one audience does not satisfy another claim"},
	"ZK-ORC-001": {"critical", "One error code for every verification failure"},
	"ZK-ORC-002": {"critical", "The enrolment path is timing-equalized"},
	"ZK-ORC-003": {"essential", "The internal detail never reaches the client"},
	"ZK-ORC-004": {"essential", "Unknown and retired roots are indistinguishable"},
	"ZK-ORC-005": {"essential", "Nullifier existence is not observable"},
	"ZK-ORC-006": {"essential", "Claim existence is not observable"},
	"ZK-ORC-007": {"essential", "Failure paths do not differ in observable side effects"},
	"ZK-PSD-002": {"critical", "Concurrent first sight creates one account"},
	"ZK-PSD-004": {"critical", "A pseudonym has no password and no verified mailbox"},
	"ZK-PSD-005": {"essential", "Principal gains no field and Scope needs no branch"},
	"ZK-PSD-006": {"essential", "Re-issuance produces a new pseudonym, and that is documented"},
	"ZK-SES-002": {"critical", "Metadata suppression is not configurable"},
	"ZK-SES-003": {"essential", "No zk artifact reaches a log"},
	"ZK-SES-007": {"essential", "issued_to is the operator's map and nothing more"},
	"ZK-SES-009": {"good-to-have", "Threshold disclosure narrows the attribute"},
	"ZK-SQL-001": {"critical", "0002_zk.sql alters no core table"},
	"ZK-SQL-003": {"critical", "The schema prefix is validated"},
	"ZK-SQL-004": {"essential", "All zk SQL lives in one sql.go per package"},
	"ZK-SQL-005": {"essential", "Errors are classified by SQLSTATE"},
	"ZK-SQL-006": {"essential", "Cascades are exactly as specified"},
	"ZK-SQL-007": {"essential", "RLS still applies to zk-created rows"},
	"ZK-SQL-008": {"good-to-have", "The migration is idempotent and ordered"},
	"ZK-TRE-002": {"critical", "The advisory lock is taken before the first read"},
	"ZK-TRE-003": {"essential", "The advisory lock key is namespaced"},
	"ZK-TRE-008": {"essential", "The grace window closes"},
	"ZK-TRE-009": {"essential", "Sparse zero-hashes resolve absent nodes"},
	"ZK-TRE-010": {"critical", "zeros[0] is domain-tagged, not 0"},
}

// zkRoadmapPinned is the number of documented cases still awaiting a test. Lower it as they land.
const zkRoadmapPinned = 78

// The group is [A-Z0-9]+, not [A-Z]+: the E2E group carries a digit, and a letters-only class
// silently drops all six ZK-E2E cases — four of them CRITICAL — from the register the manifest
// believes it is reconciling. The disposition map then names an id the test cannot see, which is
// the only reason ZK-E2E-006 ever read as `extra`.
var zkCaseHeadingRE = regexp.MustCompile(`^### (ZK-[A-Z0-9]+-[0-9]{3})\b`)

// Matched against ast.CommentGroup.Text(), which strips the `// ` markers. Anchoring on a literal
// `// Covers:` therefore never matches, `covered` stays empty for every id, and the reconciliation
// below reports the entire register as uncovered no matter how many tests cite a case.
var zkCaseCoverRE = regexp.MustCompile(`(?m)^Covers: ((?:ZK-[A-Z0-9]+-[0-9]{3})(?:, ZK-[A-Z0-9]+-[0-9]{3})*)$`)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func documentedZKCases(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "vulnurability-test-cases.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		match := zkCaseHeadingRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if out[match[1]] {
			t.Fatalf("duplicate vulnerability case heading %s", match[1])
		}
		out[match[1]] = true
	}
	return out
}

// Covers: ZK-INV-003, ZK-INV-004
func TestZKINV003ExternalCaseCoverage(t *testing.T) {
	documented := documentedZKCases(t)
	if len(documented) != 147 {
		t.Fatalf("documented ZK cases = %d, want the pinned register of 147", len(documented))
	}

	root := repositoryRoot(t)
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		files, err := filepath.Glob(filepath.Join(root, pkg, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 {
			t.Errorf("internal test files violate the external-package invariant: %v", files)
		}
	}

	testFiles, err := filepath.Glob(filepath.Join(root, "tests", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string][]string)
	fset := token.NewFileSet()
	for _, name := range testFiles {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(fset, name, raw, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if parsed.Name.Name != "tests" {
			t.Errorf("%s uses package %s, want tests", name, parsed.Name.Name)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Doc == nil {
				continue
			}
			matches := zkCaseCoverRE.FindAllStringSubmatch(fn.Doc.Text(), -1)
			for _, match := range matches {
				for _, id := range strings.Split(match[1], ", ") {
					covered[id] = append(covered[id], fn.Name.Name)
					if strings.Contains(fn.Name.Name, "DB") && !strings.HasPrefix(fn.Name.Name, "TestDBZK") {
						t.Errorf("database ZK test %s does not use the TestDBZK prefix", fn.Name.Name)
					}
				}
			}
		}
	}

	if len(zkRoadmapCases) != zkRoadmapPinned {
		t.Fatalf("roadmap holds %d cases, want the pinned %d — moving one out is progress, and it "+
			"is meant to be visible in the diff", len(zkRoadmapCases), zkRoadmapPinned)
	}

	var missing, extra []string
	for id := range documented {
		if len(covered[id]) != 0 {
			continue
		}
		_, excused := zkNonAutomatedCases[id]
		_, scheduled := zkRoadmapCases[id]
		if excused && scheduled {
			t.Errorf("%s is both excused and scheduled; it is one or the other", id)
		}
		if !excused && !scheduled {
			missing = append(missing, id)
		}
	}
	for id, disposition := range zkRoadmapCases {
		if !documented[id] {
			extra = append(extra, id)
		}
		if disposition.reason == "" {
			t.Errorf("%s has an empty roadmap rationale", id)
		}
		if len(covered[id]) != 0 {
			t.Errorf("%s is on the roadmap but %v already covers it", id, covered[id])
		}
	}
	for id := range covered {
		if !documented[id] {
			extra = append(extra, id)
		}
	}
	for id, disposition := range zkNonAutomatedCases {
		if !documented[id] {
			extra = append(extra, id)
		}
		if disposition.reason == "" {
			t.Errorf("%s has an empty %s rationale", id, disposition.kind)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("case register mismatch: missing=%v extra=%v", missing, extra)
	}
}
