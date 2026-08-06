package zkauthn

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"

	"github.com/ulas96/kal/kalerr"
)

// Credential @notice A membership credential returned once when the operator issues it.
type Credential struct {
	Secret    Secret
	Attribute uint64
	LeafIndex uint32
	Path      MerklePath
}

// MerklePath @notice The current root and sibling path for one credential leaf.
type MerklePath struct {
	Root  Field
	Path  [MerkleDepth + 1]Field
	Index uint32
}

// IssueCredential @notice Generates, inserts and returns one linked membership credential.
//
// @dev issuedTo is normally the named auth_users id so revocation can name a person. Empty
// deliberately stores NULL for deployments that prefer an unlinked issuance registry.
func (z *ZK) IssueCredential(ctx context.Context, db orm.DB, issuedTo string, attribute uint64) (*Credential, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}
	commitment, err := membershipLeaf(secret, attribute)
	if err != nil {
		return nil, err
	}
	credential := &Credential{Secret: secret, Attribute: attribute}
	err = withTx(ctx, db, func(tx orm.DB) error {
		if _, err := tx.ExecContext(ctx, z.sql.lockTree); err != nil {
			return err
		}
		var next uint64
		if _, err := tx.QueryOneContext(ctx, pg.Scan(&next), z.sql.nextLeaf); err != nil {
			return err
		}
		if next > math.MaxUint32 {
			return invalidInput("ZK membership tree is full")
		}
		index := uint32(next) // #nosec G115 -- bounded to MaxUint32 immediately above
		if _, err := tx.ExecContext(ctx, z.sql.insertCredential, next, commitment[:], issuedTo); err != nil {
			return err
		}
		root, err := z.writeLeaf(ctx, tx, index, commitment, false)
		if err != nil {
			return err
		}
		path, err := z.path(ctx, tx, index, commitment, root)
		if err != nil {
			return err
		}
		credential.LeafIndex, credential.Path = index, path
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("zkauthn: issue credential: %w", err)
	}
	return credential, nil
}

// Path @notice Returns the current Merkle path for an active credential index.
//
// @dev A path and its root are one logical snapshot, and a proof built across a mutation verifies
// against no published root at all (gotcha 54). That reasoning is right; taking the deployment-wide
// writer lock to get it was the wrong tool. Every member fetches a path before proving, so path
// reads serialized across the whole deployment, each holding a connection for 33 round-trips while
// excluding writers it never conflicts with.
//
// Instead: read the root, walk, read it again. Equal roots mean nothing was published across the
// walk and the path is a real snapshot. One retry, because a second collision means genuine write
// pressure rather than an unlucky interleaving, and spinning here is what the lock was for.
//
// ponytail: optimistic, not locked — two extra root reads per path against a deployment-wide
// serialization point. If issuance ever becomes hot enough that the retry fires routinely, the
// upgrade is a repeatable-read transaction, not the advisory lock.
func (z *ZK) Path(ctx context.Context, db orm.DB, index uint32) (*MerklePath, error) {
	var out MerklePath
	err := withTx(ctx, db, func(tx orm.DB) error {
		var raw []byte
		var revoked bool
		if _, err := tx.QueryOneContext(ctx, pg.Scan(&raw, &revoked), z.sql.credentialByIndex, uint64(index)); err != nil {
			if errors.Is(err, pg.ErrNoRows) {
				return invalidInput("unknown membership credential")
			}
			return err
		}
		if revoked {
			return invalidInput("membership credential is revoked")
		}
		commitment, err := parseField(raw)
		if err != nil {
			return fmt.Errorf("zkauthn: stored credential: %w", err)
		}
		for attempt := 0; attempt < 2; attempt++ {
			root, err := z.currentRoot(ctx, tx)
			if err != nil {
				return err
			}
			candidate, err := z.path(ctx, tx, index, commitment, root)
			if err != nil {
				return err
			}
			after, err := z.currentRoot(ctx, tx)
			if err != nil {
				return err
			}
			if root == after {
				out = candidate
				return nil
			}
		}
		return &kalerr.Error{Code: kalerr.CodeRateLimited, Message: "please try again shortly",
			Internal: errors.New("zkauthn: the credential tree moved twice during a path read")}
	})
	return &out, err
}

// RevokeCredential @notice Removes one active leaf and publishes the resulting root atomically.
func (z *ZK) RevokeCredential(ctx context.Context, db orm.DB, index uint32) error {
	return withTx(ctx, db, func(tx orm.DB) error {
		if _, err := tx.ExecContext(ctx, z.sql.lockTree); err != nil {
			return err
		}
		var ignored []byte
		if _, err := tx.QueryOneContext(ctx, pg.Scan(&ignored), z.sql.markRevoked, uint64(index)); err != nil {
			if errors.Is(err, pg.ErrNoRows) {
				return nil
			}
			return err
		}
		_, err := z.writeLeaf(ctx, tx, index, Field{}, true)
		return err
	})
}

// RevokeCredentialsForUser @notice Revokes every live credential linked to a named user.
func (z *ZK) RevokeCredentialsForUser(ctx context.Context, db orm.DB, userID string) error {
	type leafRow struct {
		LeafIndex uint64 `pg:"leaf_index"`
	}
	return withTx(ctx, db, func(tx orm.DB) error {
		if _, err := tx.ExecContext(ctx, z.sql.lockTree); err != nil {
			return err
		}
		var rows []leafRow
		if _, err := tx.QueryContext(ctx, &rows, z.sql.credentialsByUser, userID); err != nil {
			return err
		}
		for _, row := range rows {
			if row.LeafIndex > math.MaxUint32 {
				return fmt.Errorf("zkauthn: stored leaf index exceeds depth")
			}
			var ignored []byte
			if _, err := tx.QueryOneContext(ctx, pg.Scan(&ignored), z.sql.markRevoked, row.LeafIndex); err != nil {
				return err
			}
			if _, err := z.writeLeaf(ctx, tx, uint32(row.LeafIndex), Field{}, true); err != nil { // #nosec G115 -- checked above
				return err
			}
		}
		return nil
	})
}

func (z *ZK) writeLeaf(ctx context.Context, db orm.DB, index uint32, commitment Field, empty bool) (Field, error) {
	var current Field
	var err error
	if empty {
		current = z.zeros[0]
	} else {
		// gnark's Merkle gadget hashes Path[0] before its first sibling combination.
		current, err = nativeHash(commitment)
		if err != nil {
			return Field{}, err
		}
	}
	position := uint64(index)
	for level := 0; level < MerkleDepth; level++ {
		if current == z.zeros[level] {
			if _, err := db.ExecContext(ctx, z.sql.deleteNode, level, position); err != nil {
				return Field{}, err
			}
		} else if _, err := db.ExecContext(ctx, z.sql.upsertNode, level, position, current[:]); err != nil {
			return Field{}, err
		}
		sibling, err := z.node(ctx, db, level, position^1)
		if err != nil {
			return Field{}, err
		}
		if position&1 == 0 {
			current, err = nativeHash(current, sibling)
		} else {
			current, err = nativeHash(sibling, current)
		}
		if err != nil {
			return Field{}, err
		}
		position >>= 1
	}
	if _, err := db.ExecContext(ctx, z.sql.retireRoot); err != nil {
		return Field{}, err
	}
	if _, err := db.ExecContext(ctx, z.sql.insertRoot, current[:]); err != nil {
		return Field{}, err
	}
	return current, nil
}

func (z *ZK) node(ctx context.Context, db orm.DB, level int, index uint64) (Field, error) {
	var raw []byte
	_, err := db.QueryOneContext(ctx, pg.Scan(&raw), z.sql.nodeByPosition, level, index)
	if errors.Is(err, pg.ErrNoRows) {
		return z.zeros[level], nil
	}
	if err != nil {
		return Field{}, err
	}
	return parseField(raw)
}

func (z *ZK) currentRoot(ctx context.Context, db orm.DB) (Field, error) {
	var raw []byte
	_, err := db.QueryOneContext(ctx, pg.Scan(&raw), z.sql.currentRoot)
	if errors.Is(err, pg.ErrNoRows) {
		return z.zeros[MerkleDepth], nil
	}
	if err != nil {
		return Field{}, err
	}
	return parseField(raw)
}

func (z *ZK) path(ctx context.Context, db orm.DB, index uint32, commitment, root Field) (MerklePath, error) {
	out := MerklePath{Root: root, Index: index}
	out.Path[0] = commitment
	position := uint64(index)
	for level := 0; level < MerkleDepth; level++ {
		sibling, err := z.node(ctx, db, level, position^1)
		if err != nil {
			return MerklePath{}, err
		}
		out.Path[level+1] = sibling
		position >>= 1
	}
	return out, nil
}

func (z *ZK) rootAccepted(ctx context.Context, db orm.DB, root Field) (bool, error) {
	seconds := z.rootGrace.Seconds()
	var ok bool
	_, err := db.QueryOneContext(ctx, pg.Scan(&ok), z.sql.rootAccepted, root[:], seconds, seconds)
	return ok, err
}

// EnsureClaim @notice Idempotently installs the server policy for one schema claim name.
func (z *ZK) EnsureClaim(ctx context.Context, db orm.DB, claim Claim) error {
	if claim.Name == "" || len(claim.Name) > 128 {
		return invalidInput("ZK claim name must contain 1 to 128 bytes")
	}
	if claim.Kind != ClaimRecurring && claim.Kind != ClaimOneShot {
		return invalidInput("ZK claim kind must be recurring or one_shot")
	}
	if claim.Threshold > math.MaxInt64 {
		return invalidInput("ZK claim threshold exceeds Postgres bigint")
	}
	_, err := db.ExecContext(ctx, z.sql.upsertClaim,
		claim.Name, claim.Audience[:], claim.Threshold, string(claim.Kind), claim.AllowsLogin)
	return err
}

func (z *ZK) claim(ctx context.Context, db orm.DB, name string) (Claim, error) {
	var raw []byte
	var threshold uint64
	var kind string
	var allowsLogin bool
	_, err := db.QueryOneContext(ctx, pg.Scan(&raw, &threshold, &kind, &allowsLogin), z.sql.claimByName, name)
	if err != nil {
		return Claim{}, noRowsInvalid(err)
	}
	audience, err := parseField(raw)
	if err != nil {
		return Claim{}, err
	}
	return Claim{Name: name, Audience: audience, Threshold: threshold, Kind: ClaimKind(kind),
		AllowsLogin: allowsLogin}, nil
}

// Claim @notice Reads the server policy clients must use as membership public inputs.
func (z *ZK) Claim(ctx context.Context, db orm.DB, name string) (Claim, error) {
	return z.claim(ctx, db, name)
}

// RootGrace @notice Reports the configured revocation-latency allowance.
func (z *ZK) RootGrace() time.Duration { return z.rootGrace }
