package zkauthn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// Field @notice A canonical, big-endian BN254 scalar-field encoding.
type Field [fr.Bytes]byte

// Secret @notice A generated 248-bit credential that is always a canonical field element.
type Secret [SecretSize]byte

func domainElement(s string) *big.Int {
	if len(s) > SecretSize {
		panic("zkauthn: domain label exceeds canonical field width")
	}
	return new(big.Int).SetBytes([]byte(s))
}

func elementBytes(v *big.Int) Field {
	var e fr.Element
	e.SetBigInt(v)
	return e.Bytes()
}

func parseField(raw []byte) (Field, error) {
	var out Field
	if len(raw) != len(out) {
		return out, errors.New("field element must be exactly 32 bytes")
	}
	copy(out[:], raw)
	var e fr.Element
	if err := e.SetBytesCanonical(out[:]); err != nil {
		return Field{}, errors.New("field element is not canonical BN254")
	}
	return out, nil
}

func secretField(secret Secret) Field {
	var out Field
	copy(out[len(out)-len(secret):], secret[:])
	return out
}

func uint64Field(v uint64) Field {
	var e fr.Element
	e.SetUint64(v)
	return e.Bytes()
}

func nativeHash(values ...Field) (Field, error) {
	h := nativemimc.NewMiMC()
	for _, value := range values {
		if _, err := h.Write(value[:]); err != nil {
			return Field{}, fmt.Errorf("zkauthn: MiMC input: %w", err)
		}
	}
	sum := h.Sum(nil)
	var out Field
	copy(out[:], sum)
	return out, nil
}

func hashWithDomain(domain *big.Int, values ...Field) (Field, error) {
	all := make([]Field, 0, len(values)+1)
	all = append(all, elementBytes(domain))
	all = append(all, values...)
	return nativeHash(all...)
}

func knowledgeCommitment(secret Secret) (Field, error) {
	return hashWithDomain(domainKnowledge, secretField(secret))
}

// KnowledgeCommitment @notice Computes the public commitment a client proves knowledge of.
func KnowledgeCommitment(secret Secret) (Field, error) { return knowledgeCommitment(secret) }

func membershipLeaf(secret Secret, attribute uint64) (Field, error) {
	return hashWithDomain(domainLeaf, secretField(secret), uint64Field(attribute))
}

// MembershipCommitment @notice Computes the raw credential leaf bound to secret and attribute.
func MembershipCommitment(secret Secret, attribute uint64) (Field, error) {
	return membershipLeaf(secret, attribute)
}

func nullifierFor(secret Secret, audience Field) (Field, error) {
	return hashWithDomain(domainNullifier, secretField(secret), audience)
}

func emptyLeaf() (Field, error) { return hashWithDomain(domainEmpty) }

func generateSecret() (Secret, error) {
	var secret Secret
	if _, err := rand.Read(secret[:]); err != nil {
		return Secret{}, fmt.Errorf("zkauthn: generate secret: %w", err)
	}
	return secret, nil
}

// NewAudience @notice Derives a canonical audience field from deployment and policy labels.
//
// @dev SHA-256 output is reduced deliberately into BN254. Audience collision resistance is
// therefore the field size (~254 bits), and the versioned prefix prevents reuse by another
// protocol in the same process.
func NewAudience(deployment, policy, epoch string) Field {
	sum := sha256.Sum256([]byte("kal.zk.v1/audience|" + deployment + "|" + policy + "|" + epoch))
	var e fr.Element
	e.SetBytes(sum[:])
	return e.Bytes()
}

func newChallengeToken() (token string, field Field, hash [sha256.Size]byte, err error) {
	var raw [SecretSize]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", Field{}, hash, fmt.Errorf("zkauthn: generate challenge: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw[:])
	copy(field[len(field)-len(raw):], raw[:])
	hash = sha256.Sum256([]byte(token))
	return token, field, hash, nil
}

func challengeField(token string) (Field, [sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != SecretSize {
		return Field{}, hash, errors.New("invalid challenge encoding")
	}
	var field Field
	copy(field[len(field)-len(raw):], raw)
	hash = sha256.Sum256([]byte(token))
	return field, hash, nil
}

func fieldBig(v Field) *big.Int { return new(big.Int).SetBytes(v[:]) }
