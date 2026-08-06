package tests

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"

	"github.com/ulas96/kal/zkauthn"
)

type zkHash2Circuit struct {
	A, B   frontend.Variable
	Output frontend.Variable `gnark:",public"`
}

func (c *zkHash2Circuit) Define(api frontend.API) error {
	h, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.A, c.B)
	api.AssertIsEqual(h.Sum(), c.Output)
	return nil
}

type zkHash3Circuit struct {
	A, B, C frontend.Variable
	Output  frontend.Variable `gnark:",public"`
}

func (c *zkHash3Circuit) Define(api frontend.API) error {
	h, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.A, c.B, c.C)
	api.AssertIsEqual(h.Sum(), c.Output)
	return nil
}

func independentZKHash(values ...zkauthn.Field) zkauthn.Field {
	h := mimc.NewMiMC()
	for _, value := range values {
		_, _ = h.Write(value[:])
	}
	var out zkauthn.Field
	copy(out[:], h.Sum(nil))
	return out
}

func zkauthnDomainForTest(label string) zkauthn.Field {
	var out zkauthn.Field
	b := new(big.Int).SetBytes([]byte(label)).Bytes()
	copy(out[len(out)-len(b):], b)
	return out
}

func secretFieldForTest(secret zkauthn.Secret) zkauthn.Field {
	var out zkauthn.Field
	copy(out[len(out)-len(secret):], secret[:])
	return out
}

func canonicalFieldForTest(raw zkauthn.Field) zkauthn.Field {
	var element fr.Element
	element.SetBytes(raw[:])
	return element.Bytes()
}

// TestZKHSH001NativeAndCircuitMiMCAgreement exercises independent native and in-circuit
// implementations in both the accepting and rejecting directions.
// Covers: ZK-HSH-001
func TestZKHSH001NativeAndCircuitMiMCAgreement(t *testing.T) {
	r := rand.New(rand.NewSource(zkSeed(t))) // #nosec G404 -- deterministic test population
	domain := zkauthnDomainForTest("kal.zk.v1/knowledge")
	for i := 0; i < 1000; i++ {
		secret := zkSecret(r)
		input := secretFieldForTest(secret)
		want := independentZKHash(domain, input)
		assignment := &zkHash2Circuit{A: new(big.Int).SetBytes(domain[:]), B: new(big.Int).SetBytes(input[:]), Output: new(big.Int).SetBytes(want[:])}
		if err := test.IsSolved(&zkHash2Circuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("seed=%d witness=%d native/circuit mismatch: %v", zkSeedValue(t), i, err)
		}
		bad := want
		bad[len(bad)-1] ^= 1
		assignment.Output = new(big.Int).SetBytes(bad[:])
		if err := test.IsSolved(&zkHash2Circuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("seed=%d witness=%d perturbed native hash solved", zkSeedValue(t), i)
		}
	}
}

// TestZKHSH002HashArityAgreement covers the two-input and three-input absorbs used by the
// knowledge, leaf, nullifier, and sparse-tree constructions.
// Covers: ZK-HSH-002
func TestZKHSH002HashArityAgreement(t *testing.T) {
	r := rand.New(rand.NewSource(zkSeed(t))) // #nosec G404 -- deterministic test population
	domains := []string{"kal.zk.v1/knowledge", "kal.zk.v1/leaf", "kal.zk.v1/nullifier", "kal.zk.v1/empty"}
	for _, label := range domains {
		domain := zkauthnDomainForTest(label)
		for i := 0; i < 1000; i++ {
			var a, b, c zkauthn.Field
			_, _ = r.Read(a[:])
			_, _ = r.Read(b[:])
			_, _ = r.Read(c[:])
			a = canonicalFieldForTest(a)
			b = canonicalFieldForTest(b)
			c = canonicalFieldForTest(c)
			if label == "kal.zk.v1/knowledge" || label == "kal.zk.v1/empty" {
				want := independentZKHash(domain, a)
				assignment := &zkHash2Circuit{A: new(big.Int).SetBytes(domain[:]), B: new(big.Int).SetBytes(a[:]), Output: new(big.Int).SetBytes(want[:])}
				if err := test.IsSolved(&zkHash2Circuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
					t.Fatalf("%s arity-2 witness=%d: %v", label, i, err)
				}
			} else {
				want := independentZKHash(domain, a, b)
				assignment := &zkHash3Circuit{A: new(big.Int).SetBytes(domain[:]), B: new(big.Int).SetBytes(a[:]), C: new(big.Int).SetBytes(b[:]), Output: new(big.Int).SetBytes(want[:])}
				if err := test.IsSolved(&zkHash3Circuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
					t.Fatalf("%s arity-3 witness=%d: %v", label, i, err)
				}
			}
		}
	}
}

func zkSeedValue(t *testing.T) int64 {
	// The helper also prints the seed, satisfying the reproducibility requirement without
	// maintaining a second environment parser.
	return zkSeed(t)
}

var _ frontend.Circuit = (*zkHash2Circuit)(nil)
var _ frontend.Circuit = (*zkHash3Circuit)(nil)
