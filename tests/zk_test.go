package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/ulas96/kal/zkauthn"
)

func zkSeed(t *testing.T) int64 {
	t.Helper()
	seed := int64(20260805)
	if raw := os.Getenv("KAL_ZK_TEST_SEED"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			t.Fatalf("KAL_ZK_TEST_SEED: %v", err)
		}
		seed = parsed
	}
	t.Logf("zk witness seed=%d", seed)
	return seed
}

func zkSecret(r *rand.Rand) zkauthn.Secret {
	var secret zkauthn.Secret
	_, _ = r.Read(secret[:])
	return secret
}

func knowledgeAssignment(w zkauthn.KnowledgeWitness) *zkauthn.KnowledgeCircuit {
	return &zkauthn.KnowledgeCircuit{
		Commitment: new(big.Int).SetBytes(w.Commitment[:]),
		Challenge:  new(big.Int).SetBytes(w.Challenge[:]),
		Secret:     new(big.Int).SetBytes(w.Secret[:]),
	}
}

func membershipAssignment(w zkauthn.MembershipWitness) *zkauthn.MembershipCircuit {
	c := &zkauthn.MembershipCircuit{
		Root: new(big.Int).SetBytes(w.Root[:]), Audience: new(big.Int).SetBytes(w.Audience[:]),
		Threshold: w.Threshold, Nullifier: new(big.Int).SetBytes(w.Nullifier[:]),
		Challenge: new(big.Int).SetBytes(w.Challenge[:]), Secret: new(big.Int).SetBytes(w.Secret[:]),
		Attribute: w.Attribute, Index: w.Index,
	}
	for i := range w.Path {
		c.Path[i] = new(big.Int).SetBytes(w.Path[i][:])
	}
	return c
}

// TestZKDifferential compares each circuit with its readable Go predicate in both directions.
// Covers: ZK-CIR-002, ZK-CIR-003
func TestZKDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(zkSeed(t))) // #nosec G404 -- deterministic adversarial test data
	field := ecc.BN254.ScalarField()

	t.Run("knowledge", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			secret := zkSecret(r)
			commitment, err := zkauthn.KnowledgeCommitment(secret)
			if err != nil {
				t.Fatal(err)
			}
			w := zkauthn.KnowledgeWitness{
				Secret: secret, Commitment: commitment,
				Challenge: zkauthn.NewAudience("test", "knowledge", string(rune(i))),
			}
			if i%2 == 1 {
				w.Commitment[31] ^= 1
			}
			want := zkauthn.KnowledgeValid(w)
			got := test.IsSolved(&zkauthn.KnowledgeCircuit{}, knowledgeAssignment(w), field) == nil
			if got != want {
				t.Fatalf("witness %d: circuit=%v oracle=%v", i, got, want)
			}
		}
	})

	t.Run("membership", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			secret := zkSecret(r)
			attribute := uint64(r.Intn(100))
			commitment, err := zkauthn.MembershipCommitment(secret, attribute)
			if err != nil {
				t.Fatal(err)
			}
			path, err := zkauthn.SingleLeafPath(commitment)
			if err != nil {
				t.Fatal(err)
			}
			audience := zkauthn.NewAudience("test", "membership", "v1")
			nullifier, err := zkauthn.Nullifier(secret, audience)
			if err != nil {
				t.Fatal(err)
			}
			w := zkauthn.MembershipWitness{
				Secret: secret, Attribute: attribute, Path: path.Path, Index: 0, Root: path.Root,
				Audience: audience, Threshold: attribute, Nullifier: nullifier,
				Challenge: zkauthn.NewAudience("test", "challenge", string(rune(i))),
			}
			switch i % 7 {
			case 1:
				w.Threshold = attribute + 1
			case 2:
				w.Path[0][31] ^= 1
			case 3:
				w.Path[7][31] ^= 1
			case 4:
				w.Nullifier[31] ^= 1
			case 5:
				w.Index = 1
			case 6:
				w.Attribute++
			}
			want := zkauthn.MembershipValid(w)
			got := test.IsSolved(&zkauthn.MembershipCircuit{}, membershipAssignment(w), field) == nil
			if got != want {
				t.Fatalf("witness %d case %d: circuit=%v oracle=%v", i, i%7, got, want)
			}
		}
	})
}

// TestZKCIR001PublicInputBinding verifies pre-existing proofs against tampered public
// witnesses. Re-solving the tampered assignment would be a false pass for an unconstrained
// public input, so this deliberately goes through the verifying key.
// Covers: ZK-CIR-001
func TestZKCIR001PublicInputBinding(t *testing.T) {
	keys := testZKArtifacts(t)
	secret := zkauthn.Secret{1, 2, 3, 4}
	challenge := zkauthn.NewAudience("binding", "challenge", "one")
	commitment, err := zkauthn.KnowledgeCommitment(secret)
	if err != nil {
		t.Fatal(err)
	}
	knowledgeProof, err := keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secret, Commitment: commitment, Challenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.knowledgeVK.VerifyKnowledge(knowledgeProof, commitment, challenge); err != nil {
		t.Fatalf("honest knowledge proof: %v", err)
	}

	attribute := uint64(21)
	leaf, err := zkauthn.MembershipCommitment(secret, attribute)
	if err != nil {
		t.Fatal(err)
	}
	path, err := zkauthn.SingleLeafPath(leaf)
	if err != nil {
		t.Fatal(err)
	}
	audience := zkauthn.NewAudience("binding", "membership", "one")
	nullifier, err := zkauthn.Nullifier(secret, audience)
	if err != nil {
		t.Fatal(err)
	}
	membershipChallenge := zkauthn.NewAudience("binding", "challenge", "membership")
	witness := zkauthn.MembershipWitness{
		Secret: secret, Attribute: attribute, Path: path.Path, Index: path.Index,
		Root: path.Root, Audience: audience, Threshold: 18,
		Nullifier: nullifier, Challenge: membershipChallenge,
	}
	membershipProof, err := keys.membershipPK.ProveMembership(witness)
	if err != nil {
		t.Fatal(err)
	}
	public := zkauthn.MembershipPublic{Root: path.Root, Audience: audience, Threshold: 18,
		Nullifier: nullifier, Challenge: membershipChallenge}
	if err := keys.membershipVK.VerifyMembership(membershipProof, public); err != nil {
		t.Fatalf("honest membership proof: %v", err)
	}

	modulus := ecc.BN254.ScalarField()
	rMinusOne := new(big.Int).Sub(new(big.Int).Set(modulus), big.NewInt(1))
	fieldVariants := func(original zkauthn.Field) []zkauthn.Field {
		zero := zkauthn.Field{}
		rm1 := zkauthn.Field{}
		rm1Big := rMinusOne.Bytes()
		copy(rm1[len(rm1)-len(rm1Big):], rm1Big)
		random := original
		random[0] ^= 0x80
		return []zkauthn.Field{random, zero, rm1}
	}
	for _, tampered := range fieldVariants(commitment) {
		if err := keys.knowledgeVK.VerifyKnowledge(knowledgeProof, tampered, challenge); err == nil {
			t.Fatalf("knowledge proof accepted tampered commitment %x", tampered)
		}
	}
	for _, tampered := range fieldVariants(challenge) {
		if err := keys.knowledgeVK.VerifyKnowledge(knowledgeProof, commitment, tampered); err == nil {
			t.Fatalf("knowledge proof accepted tampered challenge %x", tampered)
		}
	}

	fields := []struct {
		name string
		set  func(*zkauthn.MembershipPublic, zkauthn.Field)
		orig zkauthn.Field
	}{
		{"Root", func(p *zkauthn.MembershipPublic, v zkauthn.Field) { p.Root = v }, public.Root},
		{"Audience", func(p *zkauthn.MembershipPublic, v zkauthn.Field) { p.Audience = v }, public.Audience},
		{"Nullifier", func(p *zkauthn.MembershipPublic, v zkauthn.Field) { p.Nullifier = v }, public.Nullifier},
		{"Challenge", func(p *zkauthn.MembershipPublic, v zkauthn.Field) { p.Challenge = v }, public.Challenge},
	}
	for _, field := range fields {
		for _, tampered := range fieldVariants(field.orig) {
			candidate := public
			field.set(&candidate, tampered)
			if err := keys.membershipVK.VerifyMembership(membershipProof, candidate); err == nil {
				t.Fatalf("membership proof accepted tampered %s", field.name)
			}
		}
	}

	// Threshold is the one public input the verifier holds as a uint64 rather than a Field, so it
	// gets its own variants. Routing it through fieldVariants would flip byte 0 — the most
	// significant — and the narrowing back to uint64 would discard the flip and re-derive 18, so
	// the "tampered" witness would be byte-identical to the honest one and verification would
	// correctly succeed. That is a test that can only go green.
	for _, tampered := range []uint64{0, public.Threshold - 1, public.Threshold + 1, math.MaxUint64} {
		candidate := public
		candidate.Threshold = tampered
		if err := keys.membershipVK.VerifyMembership(membershipProof, candidate); err == nil {
			t.Fatalf("membership proof accepted tampered Threshold %d", tampered)
		}
	}
}

// TestZKCircuitID pins both cost and statement identity and proves serialization is deterministic.
// Covers: ZK-CIR-015, ZK-KEY-003
func TestZKCircuitID(t *testing.T) {
	cases := []struct {
		kind        zkauthn.Circuit
		constraints int
		id          string
	}{
		{zkauthn.CircuitKnowledge, zkauthn.KnowledgeConstraints, zkauthn.KnowledgeCircuitID},
		{zkauthn.CircuitMembership, zkauthn.MembershipConstraints, zkauthn.MembershipCircuitID},
	}
	for _, tc := range cases {
		n, id, err := zkauthn.CircuitInfo(tc.kind)
		if err != nil {
			t.Fatal(err)
		}
		if n != tc.constraints || hex.EncodeToString(id[:]) != tc.id {
			t.Errorf("%s = (%d,%x), want (%d,%s)", tc.kind, n, id, tc.constraints, tc.id)
		}
		_, second, err := zkauthn.CircuitInfo(tc.kind)
		if err != nil || second != id {
			t.Errorf("%s serialization is not deterministic", tc.kind)
		}
	}
	if got := zkauthn.ProofSize(); got != 164 {
		t.Errorf("compressed proof size = %d, want 164", got)
	}
}

// TestZKProofRoundTrip exercises setup, safe key loading, proving and challenge binding.
// Covers: ZK-KEY-002, ZK-KEY-006
func TestZKProofRoundTrip(t *testing.T) {
	for _, kind := range []zkauthn.Circuit{zkauthn.CircuitKnowledge, zkauthn.CircuitMembership} {
		t.Run(string(kind), func(t *testing.T) {
			var pkBytes, vkBytes bytes.Buffer
			if err := zkauthn.Setup(kind, &pkBytes, &vkBytes); err != nil {
				t.Fatal(err)
			}
			pk, err := zkauthn.LoadProvingKey(kind, bytes.NewReader(pkBytes.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(vkBytes.Bytes())
			vk, err := zkauthn.LoadVerifyingKey(kind, bytes.NewReader(vkBytes.Bytes()), hash[:])
			if err != nil {
				t.Fatal(err)
			}
			badHash := hash
			badHash[0] ^= 1
			if _, err := zkauthn.LoadVerifyingKey(kind, bytes.NewReader(vkBytes.Bytes()), badHash[:]); err == nil {
				t.Error("a verifying key with the wrong pinned hash loaded")
			}

			secret := zkauthn.Secret{1, 2, 3}
			challenge := zkauthn.NewAudience("test", "challenge", "one")
			otherChallenge := zkauthn.NewAudience("test", "challenge", "two")
			if kind == zkauthn.CircuitKnowledge {
				commitment, _ := zkauthn.KnowledgeCommitment(secret)
				proof, err := pk.ProveKnowledge(zkauthn.KnowledgeWitness{
					Secret: secret, Commitment: commitment, Challenge: challenge,
				})
				if err != nil || vk.VerifyKnowledge(proof, commitment, challenge) != nil {
					t.Fatalf("knowledge round trip: prove=%v", err)
				}
				if err := vk.VerifyKnowledge(proof, commitment, otherChallenge); err == nil {
					t.Error("knowledge proof replayed under another challenge")
				}
				return
			}
			attribute := uint64(21)
			commitment, _ := zkauthn.MembershipCommitment(secret, attribute)
			path, _ := zkauthn.SingleLeafPath(commitment)
			audience := zkauthn.NewAudience("test", "age", "v1")
			nullifier, _ := zkauthn.Nullifier(secret, audience)
			w := zkauthn.MembershipWitness{
				Secret: secret, Attribute: attribute, Path: path.Path, Root: path.Root,
				Audience: audience, Threshold: 18, Nullifier: nullifier, Challenge: challenge,
			}
			proof, err := pk.ProveMembership(w)
			public := zkauthn.MembershipPublic{Root: path.Root, Audience: audience,
				Threshold: 18, Nullifier: nullifier, Challenge: challenge}
			if err != nil || vk.VerifyMembership(proof, public) != nil {
				t.Fatalf("membership round trip: prove=%v", err)
			}
			public.Challenge = otherChallenge
			if err := vk.VerifyMembership(proof, public); err == nil {
				t.Error("membership proof replayed under another challenge")
			}
		})
	}
}

var _ frontend.Circuit = (*zkauthn.KnowledgeCircuit)(nil)
var _ frontend.Circuit = (*zkauthn.MembershipCircuit)(nil)

// membershipLayoutAssignment builds a fully-assigned membership circuit for the witness-shape
// tests. Path is [MerkleDepth+1]frontend.Variable, and frontend.NewWitness walks every leaf: one
// nil entry makes it return "can't set fr.Element with <nil>" and the test fails on its own
// construction before asserting anything. The values are distinct so a layout assertion cannot
// pass by two fields being swapped.
func membershipLayoutAssignment() *zkauthn.MembershipCircuit {
	membership := &zkauthn.MembershipCircuit{Root: 1, Audience: 2, Threshold: 3, Nullifier: 4, Challenge: 5,
		Secret: 6, Attribute: 7, Index: 8}
	for i := range membership.Path {
		membership.Path[i] = 9 + i
	}
	return membership
}

// TestZKCIR011WitnessVisibility pins both public/private counts and the declaration order.
// Covers: ZK-CIR-011
func TestZKCIR011WitnessVisibility(t *testing.T) {
	field := ecc.BN254.ScalarField()
	knowledge, err := frontend.NewWitness(&zkauthn.KnowledgeCircuit{Commitment: 1, Challenge: 2, Secret: 3}, field)
	if err != nil {
		t.Fatal(err)
	}
	knowledgePublic, err := knowledge.Public()
	if err != nil {
		t.Fatal(err)
	}
	if got := reflect.ValueOf(knowledgePublic.Vector()).Len(); got != 2 {
		t.Fatalf("knowledge public witness length = %d, want 2", got)
	}
	if got := reflect.ValueOf(knowledge.Vector()).Len(); got != 3 {
		t.Fatalf("knowledge full witness length = %d, want 3", got)
	}

	full, err := frontend.NewWitness(membershipLayoutAssignment(), field)
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if got := reflect.ValueOf(public.Vector()).Len(); got != 5 {
		t.Fatalf("membership public witness length = %d, want 5", got)
	}
	if got := reflect.ValueOf(full.Vector()).Len(); got != 5+1+1+33+1 {
		t.Fatalf("membership full witness length = %d, want 41", got)
	}
}

// TestZKCIR012PublicWitnessLayout pins the serialized public vectors to distinct values.
// Covers: ZK-CIR-012
func TestZKCIR012PublicWitnessLayout(t *testing.T) {
	field := ecc.BN254.ScalarField()
	knowledge, err := frontend.NewWitness(&zkauthn.KnowledgeCircuit{Commitment: 1, Challenge: 2, Secret: 3}, field)
	if err != nil {
		t.Fatal(err)
	}
	public, err := knowledge.Public()
	if err != nil {
		t.Fatal(err)
	}
	got, err := public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := "000000020000000000000002" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"0000000000000000000000000000000000000000000000000000000000000002"
	if hex.EncodeToString(got) != want {
		t.Fatalf("knowledge public layout = %x, want %s", got, want)
	}

	full, err := frontend.NewWitness(membershipLayoutAssignment(), field)
	if err != nil {
		t.Fatal(err)
	}
	public, err = full.Public()
	if err != nil {
		t.Fatal(err)
	}
	got, err = public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want = "000000050000000000000005" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"0000000000000000000000000000000000000000000000000000000000000002" +
		"0000000000000000000000000000000000000000000000000000000000000003" +
		"0000000000000000000000000000000000000000000000000000000000000004" +
		"0000000000000000000000000000000000000000000000000000000000000005"
	if hex.EncodeToString(got) != want {
		t.Fatalf("membership public layout = %x, want %s", got, want)
	}
}
