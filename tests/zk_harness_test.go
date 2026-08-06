// A second, deliberately independent implementation of the zk primitives: its own MiMC, its own
// zero table, its own root recomputation, and zkRawMembership — a *big.Int witness builder that
// bypasses Field canonicalisation and can therefore express the adversarial inputs the exported
// types cannot (Attribute at 2^64, Threshold at r-1, an Index past the tree).
//
// Nothing references it yet. It is the generator ZK-CIR-004 schedules and the seam ZK-13 was
// deferred for, both listed in docs/vulnurability-test-cases.md §26; deleting it to satisfy the
// linter would delete the only part of that work already done.
//
// ponytail: suppressed, not wired. Drop this directive the moment the first test uses these — the
// suppression is what stops `unused` from reporting real rot in here once it has a caller.
//
//nolint:unused // the ZK-CIR-004 harness, scheduled but not yet wired to a test
package tests

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/ulas96/kal/zkauthn"
)

const defaultZKSeed int64 = 20260805

var (
	zkDomainKnowledge = zkDomainField("kal.zk.v1/knowledge")
	zkDomainLeaf      = zkDomainField("kal.zk.v1/leaf")
	zkDomainNullifier = zkDomainField("kal.zk.v1/nullifier")
	zkDomainEmpty     = zkDomainField("kal.zk.v1/empty")
)

func zkTestRand(t *testing.T) (*mathrand.Rand, int64) {
	t.Helper()
	seed := defaultZKSeed
	if raw := os.Getenv("KAL_ZK_TEST_SEED"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			t.Fatalf("KAL_ZK_TEST_SEED=%q: %v", raw, err)
		}
		seed = parsed
	}
	t.Logf("KAL_ZK_TEST_SEED=%d", seed)
	return mathrand.New(mathrand.NewSource(seed)), seed // #nosec G404 -- reproducible adversarial witnesses
}

func zkRandomSecret(t *testing.T) zkauthn.Secret {
	t.Helper()
	var secret zkauthn.Secret
	if _, err := cryptorand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	return secret
}

func zkSecretFromRand(r *mathrand.Rand) zkauthn.Secret {
	var secret zkauthn.Secret
	_, _ = r.Read(secret[:]) // math/rand is deliberate reproducible test data.
	return secret
}

func zkFieldFromBig(v *big.Int) zkauthn.Field {
	var e fr.Element
	e.SetBigInt(v)
	return e.Bytes()
}

func zkFieldBig(v zkauthn.Field) *big.Int { return new(big.Int).SetBytes(v[:]) }

func zkDomainField(label string) zkauthn.Field {
	return zkFieldFromBig(new(big.Int).SetBytes([]byte(label)))
}

func zkSecretField(secret zkauthn.Secret) zkauthn.Field {
	var out zkauthn.Field
	copy(out[len(out)-len(secret):], secret[:])
	return out
}

func zkUint64Field(v uint64) zkauthn.Field {
	var out zkauthn.Field
	binary.BigEndian.PutUint64(out[len(out)-8:], v)
	return out
}

// zkNativeHash is deliberately independent of zkauthn's native hash helper.
func zkNativeHash(t *testing.T, values ...zkauthn.Field) zkauthn.Field {
	t.Helper()
	h := nativemimc.NewMiMC()
	for _, value := range values {
		if _, err := h.Write(value[:]); err != nil {
			t.Fatal(err)
		}
	}
	sum := h.Sum(nil)
	var out zkauthn.Field
	copy(out[:], sum)
	return out
}

func zkHashDomain(t *testing.T, domain zkauthn.Field, values ...zkauthn.Field) zkauthn.Field {
	t.Helper()
	all := make([]zkauthn.Field, 0, len(values)+1)
	all = append(all, domain)
	all = append(all, values...)
	return zkNativeHash(t, all...)
}

func zkIndependentKnowledgeCommitment(t *testing.T, secret zkauthn.Secret) zkauthn.Field {
	t.Helper()
	return zkHashDomain(t, zkDomainKnowledge, zkSecretField(secret))
}

func zkIndependentMembershipCommitment(t *testing.T, secret zkauthn.Secret, attribute uint64) zkauthn.Field {
	t.Helper()
	return zkHashDomain(t, zkDomainLeaf, zkSecretField(secret), zkUint64Field(attribute))
}

func zkIndependentNullifier(t *testing.T, secret zkauthn.Secret, audience zkauthn.Field) zkauthn.Field {
	t.Helper()
	return zkHashDomain(t, zkDomainNullifier, zkSecretField(secret), audience)
}

func zkZeroTable(t *testing.T) [zkauthn.MerkleDepth + 1]zkauthn.Field {
	t.Helper()
	var zeros [zkauthn.MerkleDepth + 1]zkauthn.Field
	zeros[0] = zkHashDomain(t, zkDomainEmpty)
	for level := 1; level <= zkauthn.MerkleDepth; level++ {
		zeros[level] = zkNativeHash(t, zeros[level-1], zeros[level-1])
	}
	return zeros
}

func zkRecomputeRoot(t *testing.T, path [zkauthn.MerkleDepth + 1]zkauthn.Field, index uint32) zkauthn.Field {
	t.Helper()
	current := zkNativeHash(t, path[0])
	for level := 0; level < zkauthn.MerkleDepth; level++ {
		if (index>>level)&1 == 0 {
			current = zkNativeHash(t, current, path[level+1])
		} else {
			current = zkNativeHash(t, path[level+1], current)
		}
	}
	return current
}

func zkKnowledgeAssignment(secret zkauthn.Secret, commitment, challenge zkauthn.Field) *zkauthn.KnowledgeCircuit {
	return &zkauthn.KnowledgeCircuit{
		Commitment: zkFieldBig(commitment),
		Challenge:  zkFieldBig(challenge),
		Secret:     zkFieldBig(zkSecretField(secret)),
	}
}

func zkMembershipAssignment(w zkauthn.MembershipWitness) *zkauthn.MembershipCircuit {
	c := &zkauthn.MembershipCircuit{
		Root: zkFieldBig(w.Root), Audience: zkFieldBig(w.Audience), Threshold: w.Threshold,
		Nullifier: zkFieldBig(w.Nullifier), Challenge: zkFieldBig(w.Challenge),
		Secret: zkFieldBig(zkSecretField(w.Secret)), Attribute: w.Attribute, Index: w.Index,
	}
	for i := range w.Path {
		c.Path[i] = zkFieldBig(w.Path[i])
	}
	return c
}

type zkRawMembership struct {
	Root, Audience, Threshold, Nullifier, Challenge *big.Int
	Secret, Attribute, Index                        *big.Int
	Path                                            [zkauthn.MerkleDepth + 1]*big.Int
}

func (w zkRawMembership) assignment() *zkauthn.MembershipCircuit {
	c := &zkauthn.MembershipCircuit{
		Root: w.Root, Audience: w.Audience, Threshold: w.Threshold,
		Nullifier: w.Nullifier, Challenge: w.Challenge,
		Secret: w.Secret, Attribute: w.Attribute, Index: w.Index,
	}
	for i := range w.Path {
		c.Path[i] = w.Path[i]
	}
	return c
}

func zkRawFromWitness(w zkauthn.MembershipWitness) zkRawMembership {
	out := zkRawMembership{
		Root: zkFieldBig(w.Root), Audience: zkFieldBig(w.Audience), Threshold: new(big.Int).SetUint64(w.Threshold),
		Nullifier: zkFieldBig(w.Nullifier), Challenge: zkFieldBig(w.Challenge),
		Secret: zkFieldBig(zkSecretField(w.Secret)), Attribute: new(big.Int).SetUint64(w.Attribute),
		Index: new(big.Int).SetUint64(uint64(w.Index)),
	}
	for i := range w.Path {
		out.Path[i] = zkFieldBig(w.Path[i])
	}
	return out
}

func zkHonestMembershipWitness(t *testing.T, secret zkauthn.Secret, attribute, threshold uint64,
	audience, challenge zkauthn.Field) zkauthn.MembershipWitness {
	t.Helper()
	commitment := zkIndependentMembershipCommitment(t, secret, attribute)
	path, err := zkauthn.SingleLeafPath(commitment)
	if err != nil {
		t.Fatal(err)
	}
	return zkauthn.MembershipWitness{
		Secret: secret, Attribute: attribute, Path: path.Path, Index: path.Index, Root: path.Root,
		Audience: audience, Threshold: threshold,
		Nullifier: zkIndependentNullifier(t, secret, audience), Challenge: challenge,
	}
}

func zkKnowledgeReference(t *testing.T, secret zkauthn.Secret, commitment zkauthn.Field) bool {
	t.Helper()
	return zkIndependentKnowledgeCommitment(t, secret) == commitment
}

func zkMembershipReference(t *testing.T, w zkRawMembership) bool {
	t.Helper()
	modulus := ecc.BN254.ScalarField()
	if w.Attribute.Sign() < 0 || w.Attribute.BitLen() > 64 || w.Threshold.Sign() < 0 || w.Threshold.BitLen() > 64 {
		return false
	}
	if w.Index.Sign() < 0 || w.Index.BitLen() > zkauthn.MerkleDepth {
		return false
	}
	if w.Secret.Sign() < 0 || w.Secret.Cmp(modulus) >= 0 {
		return false
	}
	attribute := w.Attribute.Uint64()
	var secret zkauthn.Secret
	secretBytes := w.Secret.Bytes()
	if len(secretBytes) > len(secret) {
		return false
	}
	copy(secret[len(secret)-len(secretBytes):], secretBytes)
	leaf := zkIndependentMembershipCommitment(t, secret, attribute)
	if zkFieldBig(leaf).Cmp(w.Path[0]) != 0 || w.Attribute.Cmp(w.Threshold) < 0 {
		return false
	}
	audience := zkFieldFromBig(w.Audience)
	nullifier := zkIndependentNullifier(t, secret, audience)
	if zkFieldBig(nullifier).Cmp(w.Nullifier) != 0 {
		return false
	}
	var path [zkauthn.MerkleDepth + 1]zkauthn.Field
	for i := range path {
		path[i] = zkFieldFromBig(w.Path[i])
	}
	root := zkRecomputeRoot(t, path, uint32(w.Index.Uint64())) // #nosec G115 -- bit length checked above
	return zkFieldBig(root).Cmp(w.Root) == 0
}

type zkHonestProofs struct {
	knowledgeProof, membershipProof []byte
	knowledgeCommitment             zkauthn.Field
	knowledgeChallenge              zkauthn.Field
	membershipPublic                zkauthn.MembershipPublic
	membershipWitness               zkauthn.MembershipWitness
}

var (
	zkHonestProofsOnce sync.Once
	zkHonestProofsData zkHonestProofs
	zkHonestProofsErr  error
)

func testZKHonestProofs(t *testing.T) zkHonestProofs {
	t.Helper()
	zkHonestProofsOnce.Do(func() {
		keys := testZKArtifacts(t)
		secret := zkauthn.Secret{1, 2, 3, 4, 5, 6, 7, 8}
		zkHonestProofsData.knowledgeChallenge = zkauthn.NewAudience("tests", "knowledge-proof", "v1")
		zkHonestProofsData.knowledgeCommitment = zkIndependentKnowledgeCommitment(t, secret)
		zkHonestProofsData.knowledgeProof, zkHonestProofsErr = keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
			Secret: secret, Commitment: zkHonestProofsData.knowledgeCommitment,
			Challenge: zkHonestProofsData.knowledgeChallenge,
		})
		if zkHonestProofsErr != nil {
			return
		}
		audience := zkauthn.NewAudience("tests", "membership-proof", "v1")
		challenge := zkauthn.NewAudience("tests", "membership-challenge", "v1")
		zkHonestProofsData.membershipWitness = zkHonestMembershipWitness(t, secret, 21, 18, audience, challenge)
		zkHonestProofsData.membershipProof, zkHonestProofsErr = keys.membershipPK.ProveMembership(zkHonestProofsData.membershipWitness)
		w := zkHonestProofsData.membershipWitness
		zkHonestProofsData.membershipPublic = zkauthn.MembershipPublic{
			Root: w.Root, Audience: w.Audience, Threshold: w.Threshold,
			Nullifier: w.Nullifier, Challenge: w.Challenge,
		}
	})
	if zkHonestProofsErr != nil {
		t.Fatal(zkHonestProofsErr)
	}
	return zkHonestProofsData
}

func zkParseProof(t *testing.T, raw []byte) groth16.Proof {
	t.Helper()
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return proof
}

func zkHex(v zkauthn.Field) string { return hex.EncodeToString(v[:]) }

func zkDistinctFields(values ...zkauthn.Field) error {
	seen := make(map[zkauthn.Field]bool)
	for _, value := range values {
		if value == (zkauthn.Field{}) {
			return fmt.Errorf("zero field element")
		}
		if seen[value] {
			return fmt.Errorf("duplicate field element %s", zkHex(value))
		}
		seen[value] = true
	}
	return nil
}

var _ frontend.Circuit = (*zkauthn.KnowledgeCircuit)(nil)
var _ frontend.Circuit = (*zkauthn.MembershipCircuit)(nil)
