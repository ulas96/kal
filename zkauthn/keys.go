package zkauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit identifies one setup-compatible constraint system.
type Circuit string

const (
	// CircuitKnowledge identifies KnowledgeCircuit and its setup artifacts.
	CircuitKnowledge Circuit = "knowledge-v1"
	// CircuitMembership identifies MembershipCircuit and its setup artifacts.
	CircuitMembership Circuit = "membership-v1"
)

// VerifyingKey @notice A safely parsed, hash-pinned Groth16 verifying key.
type VerifyingKey struct {
	circuit Circuit
	key     groth16.VerifyingKey
}

// ProvingKey @notice A parsed Groth16 proving key and its matching compiled circuit.
type ProvingKey struct {
	circuit Circuit
	ccs     constraint.ConstraintSystem
	key     groth16.ProvingKey
}

func compileCircuit(kind Circuit) (constraint.ConstraintSystem, error) {
	var circuit frontend.Circuit
	switch kind {
	case CircuitKnowledge:
		circuit = &KnowledgeCircuit{}
	case CircuitMembership:
		circuit = &MembershipCircuit{}
	default:
		return nil, fmt.Errorf("zkauthn: unknown circuit %q", kind)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("zkauthn: compile %s circuit: %w", kind, err)
	}
	return ccs, nil
}

func checkCircuitPin(kind Circuit, ccs constraint.ConstraintSystem) error {
	var wantConstraints int
	var wantID string
	switch kind {
	case CircuitKnowledge:
		wantConstraints, wantID = KnowledgeConstraints, KnowledgeCircuitID
	case CircuitMembership:
		wantConstraints, wantID = MembershipConstraints, MembershipCircuitID
	default:
		return fmt.Errorf("zkauthn: unknown circuit %q", kind)
	}
	if ccs.GetNbConstraints() != wantConstraints {
		return fmt.Errorf("zkauthn: %s circuit has %d constraints, pinned at %d",
			kind, ccs.GetNbConstraints(), wantConstraints)
	}
	var buf bytes.Buffer
	if _, err := ccs.WriteTo(&buf); err != nil {
		return fmt.Errorf("zkauthn: serialize %s circuit: %w", kind, err)
	}
	got := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(got[:]) != wantID {
		return fmt.Errorf("zkauthn: %s circuit identity changed", kind)
	}
	return nil
}

// Setup @notice Runs the operator ceremony for one circuit and writes separate proving and verifying keys.
//
// @dev The two writers prevent the multi-megabyte proving key from being mounted beside a
// server that only needs the verifying key. Neither output belongs in this repository.
func Setup(kind Circuit, pkw, vkw io.Writer) error {
	if pkw == nil || vkw == nil {
		return fmt.Errorf("zkauthn: both proving-key and verifying-key writers are required")
	}
	ccs, err := compileCircuit(kind)
	if err != nil {
		return err
	}
	if err := checkCircuitPin(kind, ccs); err != nil {
		return err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("zkauthn: setup %s: %w", kind, err)
	}
	if _, err := pk.WriteTo(pkw); err != nil {
		return fmt.Errorf("zkauthn: write %s proving key: %w", kind, err)
	}
	if _, err := vk.WriteTo(vkw); err != nil {
		return fmt.Errorf("zkauthn: write %s verifying key: %w", kind, err)
	}
	return nil
}

// LoadVerifyingKey @notice Hash-pins and safely parses a BN254 verifying key.
func LoadVerifyingKey(kind Circuit, r io.Reader, wantSHA256 []byte) (*VerifyingKey, error) {
	if r == nil || len(wantSHA256) != sha256.Size {
		return nil, fmt.Errorf("zkauthn: verifying key and 32-byte SHA-256 are required")
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("zkauthn: read %s verifying key: %w", kind, err)
	}
	got := sha256.Sum256(raw)
	if !bytes.Equal(got[:], wantSHA256) {
		return nil, fmt.Errorf("zkauthn: %s verifying key SHA-256 mismatch", kind)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("zkauthn: parse %s verifying key: %w", kind, err)
	}
	ccs, err := compileCircuit(kind)
	if err != nil {
		return nil, err
	}
	if err := checkCircuitPin(kind, ccs); err != nil {
		return nil, err
	}
	return &VerifyingKey{circuit: kind, key: vk}, nil
}

// LoadProvingKey @notice Safely parses a proving key for the named compiled circuit.
func LoadProvingKey(kind Circuit, r io.Reader) (*ProvingKey, error) {
	if r == nil {
		return nil, fmt.Errorf("zkauthn: proving key is required")
	}
	ccs, err := compileCircuit(kind)
	if err != nil {
		return nil, err
	}
	if err := checkCircuitPin(kind, ccs); err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("zkauthn: parse %s proving key: %w", kind, err)
	}
	return &ProvingKey{circuit: kind, ccs: ccs, key: pk}, nil
}

// CircuitInfo @notice The measured size and serialized identity of a compiled circuit.
func CircuitInfo(kind Circuit) (constraints int, id [sha256.Size]byte, err error) {
	ccs, err := compileCircuit(kind)
	if err != nil {
		return 0, id, err
	}
	var buf bytes.Buffer
	if _, err := ccs.WriteTo(&buf); err != nil {
		return 0, id, fmt.Errorf("zkauthn: serialize %s circuit: %w", kind, err)
	}
	return ccs.GetNbConstraints(), sha256.Sum256(buf.Bytes()), nil
}
