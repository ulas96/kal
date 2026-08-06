package zkauthn

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// KnowledgeWitness @notice Typed inputs for creating a knowledge proof.
type KnowledgeWitness struct {
	Secret     Secret
	Commitment Field
	Challenge  Field
}

// MembershipWitness @notice Typed inputs for creating a membership or threshold proof.
type MembershipWitness struct {
	Secret    Secret
	Attribute uint64
	Path      [MerkleDepth + 1]Field
	Index     uint32
	Root      Field
	Audience  Field
	Threshold uint64
	Nullifier Field
	Challenge Field
}

// MembershipPublic @notice The public witness supplied by the verifier after policy lookup.
type MembershipPublic struct {
	Root, Audience, Nullifier, Challenge Field
	Threshold                            uint64
}

func (w KnowledgeWitness) assignment() *KnowledgeCircuit {
	return &KnowledgeCircuit{
		Commitment: fieldBig(w.Commitment),
		Challenge:  fieldBig(w.Challenge),
		Secret:     fieldBig(secretField(w.Secret)),
	}
}

func (w MembershipWitness) assignment() *MembershipCircuit {
	c := &MembershipCircuit{
		Root: fieldBig(w.Root), Audience: fieldBig(w.Audience), Threshold: w.Threshold,
		Nullifier: fieldBig(w.Nullifier), Challenge: fieldBig(w.Challenge),
		Secret: fieldBig(secretField(w.Secret)), Attribute: w.Attribute, Index: w.Index,
	}
	for i := range w.Path {
		c.Path[i] = fieldBig(w.Path[i])
	}
	return c
}

// ProveKnowledge @notice Creates a compressed Groth16 knowledge proof.
func (p *ProvingKey) ProveKnowledge(w KnowledgeWitness) ([]byte, error) {
	if p == nil || p.circuit != CircuitKnowledge {
		return nil, fmt.Errorf("zkauthn: knowledge proving key required")
	}
	return p.prove(w.assignment())
}

// ProveMembership @notice Creates a compressed Groth16 membership proof.
func (p *ProvingKey) ProveMembership(w MembershipWitness) ([]byte, error) {
	if p == nil || p.circuit != CircuitMembership {
		return nil, fmt.Errorf("zkauthn: membership proving key required")
	}
	return p.prove(w.assignment())
}

func (p *ProvingKey) prove(assignment frontend.Circuit) ([]byte, error) {
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("zkauthn: build %s witness: %w", p.circuit, err)
	}
	proof, err := groth16.Prove(p.ccs, p.key, w)
	if err != nil {
		return nil, fmt.Errorf("zkauthn: prove %s: %w", p.circuit, err)
	}
	var out bytes.Buffer
	if _, err := proof.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("zkauthn: serialize %s proof: %w", p.circuit, err)
	}
	return out.Bytes(), nil
}

// ProofSize @notice The exact compressed proof length accepted before deserialization.
func ProofSize() int {
	proof := groth16.NewProof(ecc.BN254)
	var buf bytes.Buffer
	_, _ = proof.WriteTo(&buf)
	return buf.Len()
}

func (v *VerifyingKey) verify(raw []byte, assignment frontend.Circuit) error {
	if v == nil || v.key == nil {
		return fmt.Errorf("zkauthn: verifying key required")
	}
	if len(raw) != ProofSize() {
		return fmt.Errorf("zkauthn: proof length is %d, want %d", len(raw), ProofSize())
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("zkauthn: parse proof: %w", err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("zkauthn: build public witness: %w", err)
	}
	if err := groth16.Verify(proof, v.key, w); err != nil {
		return fmt.Errorf("zkauthn: verify proof: %w", err)
	}
	return nil
}

// VerifyKnowledge @notice Verifies proof against server-supplied commitment and challenge.
func (v *VerifyingKey) VerifyKnowledge(proof []byte, commitment, challenge Field) error {
	if v == nil || v.circuit != CircuitKnowledge {
		return fmt.Errorf("zkauthn: knowledge verifying key required")
	}
	return v.verify(proof, &KnowledgeCircuit{
		Commitment: fieldBig(commitment), Challenge: fieldBig(challenge),
	})
}

// VerifyMembership @notice Verifies proof against server-supplied policy public inputs.
func (v *VerifyingKey) VerifyMembership(proof []byte, public MembershipPublic) error {
	if v == nil || v.circuit != CircuitMembership {
		return fmt.Errorf("zkauthn: membership verifying key required")
	}
	return v.verify(proof, &MembershipCircuit{
		Root: fieldBig(public.Root), Audience: fieldBig(public.Audience),
		Threshold: public.Threshold, Nullifier: fieldBig(public.Nullifier),
		Challenge: fieldBig(public.Challenge),
	})
}

// KnowledgeValid @notice Plain-Go oracle for KnowledgeCircuit.
func KnowledgeValid(w KnowledgeWitness) bool {
	got, err := knowledgeCommitment(w.Secret)
	return err == nil && got == w.Commitment
}

// MembershipValid @notice Plain-Go oracle for MembershipCircuit.
func MembershipValid(w MembershipWitness) bool {
	leaf, err := membershipLeaf(w.Secret, w.Attribute)
	if err != nil || leaf != w.Path[0] || w.Attribute < w.Threshold {
		return false
	}
	nullifier, err := nullifierFor(w.Secret, w.Audience)
	if err != nil || nullifier != w.Nullifier {
		return false
	}
	// gnark's MerkleProof hashes Path[0] once before combining the 32 sibling nodes.
	sum, err := nativeHash(w.Path[0])
	if err != nil {
		return false
	}
	for level := 0; level < MerkleDepth; level++ {
		if (w.Index>>level)&1 == 0 {
			sum, err = nativeHash(sum, w.Path[level+1])
		} else {
			sum, err = nativeHash(w.Path[level+1], sum)
		}
		if err != nil {
			return false
		}
	}
	return sum == w.Root
}

// SingleLeafPath @notice Builds the sparse-tree path for the first and only credential.
//
// @dev This is primarily a setup smoke-test and example helper. Live clients must call Path,
// because every later enrolment changes siblings and the root.
func SingleLeafPath(commitment Field) (MerklePath, error) {
	var out MerklePath
	out.Path[0] = commitment
	zero, err := emptyLeaf()
	if err != nil {
		return MerklePath{}, err
	}
	out.Path[1] = zero
	for level := 1; level < MerkleDepth; level++ {
		out.Path[level+1], err = nativeHash(out.Path[level], out.Path[level])
		if err != nil {
			return MerklePath{}, err
		}
	}
	sum, err := nativeHash(commitment)
	if err != nil {
		return MerklePath{}, err
	}
	for level := 0; level < MerkleDepth; level++ {
		sum, err = nativeHash(sum, out.Path[level+1])
		if err != nil {
			return MerklePath{}, err
		}
	}
	out.Root = sum
	return out, nil
}
