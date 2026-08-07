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

// The same shape as zk_case_manifest_test.go, for the same reason: docs/e2ee-test-cases.md §16
// says a coverage ledger written in prose goes stale the moment a test lands, and a stale ledger
// that claims a case is discharged is worse than none — it makes an absent control read green,
// which is the exact failure docs/gotchas.md catalogues. Pinned in code, the count can only fall by
// writing a test.
//
// Nothing here is a t.Skip. A skip reports ok, and CI's `--- SKIP: TestDB` guard exists because
// that lesson was already learned once in this repository.

type e2eeCaseDisposition struct {
	kind   string
	reason string
}

// e2eeNonAutomatedCases @notice The cases a passing test does not fully discharge, each with what
// is left over and where the rest lives.
//
// @dev Two kinds, and the reconciliation below enforces the difference rather than trusting the
// label:
//
//   - "partial" — a test covers what is automatable and a residual obligation is not a code test at
//     all. These *must* be cited by a test; a partial with no coverage is an uncovered case wearing
//     an excuse.
//   - "elsewhere" — discharged in full outside the e2ee files. These must *not* be cited here, or
//     the same obligation would be claimed twice and the two copies would drift.
//
// Three entries only, and all three are placed here by the register's own text rather than
// discovered while writing the tests. Anything else that cannot be asserted from package tests is a
// finding about the exported surface (P-5), not a candidate for this map.
var e2eeNonAutomatedCases = map[string]e2eeCaseDisposition{
	"E2EE-ISO-002": {"partial", "the full procedure adds a package importing crypto/aes, imports it " +
		"from e2ee, runs, and reverts — that is mutation M-30, and it cannot live in the tree it " +
		"mutates. TestE2EEImportGraph automates the gate the mutation exercises, including a " +
		"synthetic import list carrying a module-internal crypto helper"},
	"E2EE-DOC-005": {"partial", "the register calls the code-test version of this case the false " +
		"pass: 'the doc mentions validation' is not the claim 'the code performs it'. " +
		"TestE2EEClientDocClaims carries the checklist in its doc comment, asserts the claims that " +
		"are code-backed, and pins the sentence §17.1 is about; a human reads the pairing at review"},
	"E2EE-SHM-001": {"elsewhere", "compile-time in tests/kal_test.go:142-158, in both directions for " +
		"all four types, which is the form the case demands; a runtime reflect.TypeOf comparison " +
		"here would be the weaker duplicate and would drift from it"},
}

// e2eeCaseHeadingRE @notice The register's case headings.
var e2eeCaseHeadingRE = regexp.MustCompile(`^### (E2EE-[A-Z]+-[0-9]{3})\b`)

// e2eeCaseCoverRE @notice A Covers annotation, matched against ast.CommentGroup.Text().
//
// @dev Text() strips the `// ` markers, so anchoring on a literal `// Covers:` never matches and
// every id would read as uncovered no matter how many tests cite it. The annotation may wrap
// across lines, so the ids are pulled out of the whole comment rather than one line of it.
var e2eeCaseCoverRE = regexp.MustCompile(`(?s)Covers: ((?:E2EE-[A-Z]+-[0-9]{3}(?:,\s*)?)+)`)

var e2eeCaseIDRE = regexp.MustCompile(`E2EE-[A-Z]+-[0-9]{3}`)

// documentedE2EECases @notice Every case id in docs/e2ee-test-cases.md, in register order.
func documentedE2EECases(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "e2ee-test-cases.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		match := e2eeCaseHeadingRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if out[match[1]] {
			t.Fatalf("duplicate case heading %s", match[1])
		}
		out[match[1]] = true
	}
	return out
}

// TestE2EECaseCoverage @notice Every case in the register is either discharged by a named test or
// dispositioned with a reason.
//
// @dev The reconciliation runs in both directions. An id cited by a test that the register does
// not carry is as much a defect as a case nobody tested: it means a test claims to discharge an
// obligation that does not exist, and the number in the ledger is then a number about nothing.
//
// The P-1/P-2 naming rules are checked here too, because they are the difference between a case
// that runs and a case that reports ok while skipping.
func TestE2EECaseCoverage(t *testing.T) {
	documented := documentedE2EECases(t)
	if len(documented) != 120 {
		t.Fatalf("documented e2ee cases = %d, want the pinned register of 120 — a case added to "+
			"docs/e2ee-test-cases.md is meant to be visible in this diff", len(documented))
	}

	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "tests", "e2ee*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string][]string)
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
		if parsed.Name.Name != "tests" {
			t.Errorf("%s uses package %s, want tests", name, parsed.Name.Name)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Doc == nil {
				continue
			}
			for _, match := range e2eeCaseCoverRE.FindAllStringSubmatch(fn.Doc.Text(), -1) {
				for _, id := range e2eeCaseIDRE.FindAllString(match[1], -1) {
					covered[id] = append(covered[id], fn.Name.Name)
					// P-2: CI greps `--- PASS: TestDB` and fails on `--- SKIP: TestDB`, so a
					// database case named anything else is invisible to that gate.
					if strings.HasPrefix(fn.Name.Name, "TestDB") &&
						!strings.HasPrefix(fn.Name.Name, "TestDBE2EE") {
						t.Errorf("database case %s does not use the TestDBE2EE prefix", fn.Name.Name)
					}
				}
			}
		}
	}

	var missing, extra []string
	for id := range documented {
		if len(covered[id]) != 0 {
			continue
		}
		if _, excused := e2eeNonAutomatedCases[id]; !excused {
			missing = append(missing, id)
		}
	}
	for id := range covered {
		if !documented[id] {
			extra = append(extra, id)
		}
	}
	for id, disposition := range e2eeNonAutomatedCases {
		if !documented[id] {
			extra = append(extra, id)
		}
		if disposition.reason == "" {
			t.Errorf("%s has an empty %s rationale", id, disposition.kind)
		}
		switch disposition.kind {
		case "partial":
			if len(covered[id]) == 0 {
				t.Errorf("%s is dispositioned partial and no test cites it — a partial with no "+
					"coverage is an uncovered case wearing an excuse", id)
			}
		case "elsewhere":
			if len(covered[id]) != 0 {
				t.Errorf("%s is discharged elsewhere and %v also cites it — one obligation, two "+
					"copies, and they will drift", id, covered[id])
			}
		default:
			t.Errorf("%s carries the unknown disposition kind %q", id, disposition.kind)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("case register mismatch: missing=%v extra=%v", missing, extra)
	}
}

// TestE2EENonDatabaseCasesRun @notice The cases that need no database are not named TestDB*.
//
// @dev P-1. `make test` on a machine with no DATABASE_URL skips every TestDB*, and a skip reports
// ok — so a case named that way, when it did not need Postgres, silently stops being run by the
// command most people type. The import allowlist, the auth-secret shape and the documented
// refusals are exactly the cases that must survive that.
func TestE2EENonDatabaseCasesRun(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "tests", "e2ee_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "e2ee_test.go", raw, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		found++
		if strings.HasPrefix(fn.Name.Name, "TestDB") {
			t.Errorf("%s lives in the database-free file and would skip without DATABASE_URL", fn.Name.Name)
		}
	}
	if found == 0 {
		t.Error("no tests found in e2ee_test.go — the check above passed over nothing")
	}
}
