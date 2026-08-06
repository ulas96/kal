// Package zkauthn @notice Groth16 authentication and anonymous authorization over BN254.
//
// @dev The operator that verifies proofs also performs each circuit's trusted setup. That
// operator can already bypass its own verifier, so single-party setup does not weaken the
// soundness property against users. No setup output is shipped by kal.
package zkauthn

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
)

const (
	// MerkleDepth @notice The fixed credential-tree depth and therefore part of the circuit.
	MerkleDepth = 32
	// SecretSize @notice Bytes in a generated ZK secret; every 31-byte value is canonical BN254.
	SecretSize = 31
	// KnowledgeConstraints pins the compiled R1CS cost under gnark v0.15.0.
	KnowledgeConstraints = 332
	// MembershipConstraints pins the compiled R1CS cost under gnark v0.15.0.
	//
	// @dev v0.15's two-input MiMC absorbs two field blocks at 330 constraints each, so the
	// 32 tree compressions account for ~21k constraints. The handout's 20k estimate assumed
	// one permutation per two-to-one compression; the measured API semantics are pinned here.
	MembershipConstraints = 23001
	KnowledgeCircuitID    = "27262b1163cbc35c4fb83ec828234b98dc324f9f351681cf781ccf7529c1fe3f"
	MembershipCircuitID   = "5f8c74c31dfa7fe1575ce175856d4ed02f5e657d2fb8a7d0208279ef63f6370f"
)

var (
	domainKnowledge = domainElement("kal.zk.v1/knowledge")
	domainLeaf      = domainElement("kal.zk.v1/leaf")
	domainNullifier = domainElement("kal.zk.v1/nullifier")
	domainEmpty     = domainElement("kal.zk.v1/empty")
)

// KnowledgeCircuit @notice Proves knowledge of a secret committed for the current session.
//
// @dev Flattened form:
//
//  1. h = MiMC(DOM_KNOWLEDGE, Secret)
//  2. assert h == Commitment
//  3. c2 = Challenge * Challenge
//
// Statement 3 deliberately creates an otherwise-unused constraint. Without it Challenge is
// present in the public witness but not bound to the proof, so a proof replays under every
// server challenge.
type KnowledgeCircuit struct {
	Commitment frontend.Variable `gnark:",public"`
	Challenge  frontend.Variable `gnark:",public"`
	Secret     frontend.Variable
}

// Define @notice Declares the knowledge constraints above.
func (c *KnowledgeCircuit) Define(api frontend.API) error {
	h, err := stdmimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("zkauthn: create knowledge MiMC: %w", err)
	}
	h.Write(domainKnowledge, c.Secret)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	_ = api.Mul(c.Challenge, c.Challenge)
	return nil
}

// MembershipCircuit @notice Proves membership, one numeric threshold and an audience pseudonym.
//
// @dev Flattened form:
//
//  1. decompose Attribute into exactly 64 bits
//  2. leaf = MiMC(DOM_LEAF, Secret, Attribute)
//  3. assert leaf == Path[0]
//  4. verify Path at Index recomputes Root
//  5. assert Threshold <= Attribute
//  6. n = MiMC(DOM_NULLIFIER, Secret, Audience)
//  7. assert n == Nullifier
//  8. c2 = Challenge * Challenge
//
// Path[0] is private prover input. Statement 3 is what proves knowledge of the credential
// rather than mere knowledge of any public leaf. Statement 8 binds freshness just as it does
// in KnowledgeCircuit.
type MembershipCircuit struct {
	Root      frontend.Variable `gnark:",public"`
	Audience  frontend.Variable `gnark:",public"`
	Threshold frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Challenge frontend.Variable `gnark:",public"`
	Secret    frontend.Variable
	Attribute frontend.Variable
	Path      [MerkleDepth + 1]frontend.Variable
	Index     frontend.Variable
}

// Define @notice Declares the membership constraints above.
func (c *MembershipCircuit) Define(api frontend.API) error {
	// This equality-producing decomposition must precede the comparison. Without it a field
	// value such as r-1 is interpreted as a negative integer by policy but as a huge field
	// element by the circuit.
	_ = api.ToBinary(c.Attribute, 64)

	h, err := stdmimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("zkauthn: create membership MiMC: %w", err)
	}
	h.Write(domainLeaf, c.Secret, c.Attribute)
	leaf := h.Sum()
	api.AssertIsEqual(leaf, c.Path[0])

	path := make([]frontend.Variable, len(c.Path))
	copy(path, c.Path[:])
	mp := merkle.MerkleProof{RootHash: c.Root, Path: path}
	mp.VerifyProof(api, &h, c.Index)

	maxUint64 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	cmp.NewBoundedComparator(api, maxUint64, false).AssertIsLessEq(c.Threshold, c.Attribute)
	h.Reset()
	h.Write(domainNullifier, c.Secret, c.Audience)
	api.AssertIsEqual(h.Sum(), c.Nullifier)
	_ = api.Mul(c.Challenge, c.Challenge)
	return nil
}
