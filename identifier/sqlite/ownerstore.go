package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS resource_owners (
    resource_type TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    owner_email   TEXT NOT NULL,
    PRIMARY KEY (resource_type, resource_name, owner_email)
);`

// OwnerStore is a SQLite-backed implementation of identifier.OwnerStore.
//
// Each row maps a (resource_type, resource_name, owner_email) triple to one
// ownership grant. Multiple rows for the same resource represent co-owners.
// Replace this with a gRPC-backed implementation to support distributed
// ownership checks across multiple Identifier nodes.
type OwnerStore struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at dsn and applies the schema.
// Use ":memory:" for an ephemeral in-process database.
func Open(dsn string) (*OwnerStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %q: %w", dsn, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return &OwnerStore{db: db}, nil
}

// Close releases the underlying database connection.
func (s *OwnerStore) Close() error {
	return s.db.Close()
}

// Register grants ownership of a resource (type+name) to ownerEmail.
// Calling Register again for the same (resource, email) triple is a no-op.
func (s *OwnerStore) Register(ctx context.Context, resourceType, resourceName, ownerEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO resource_owners (resource_type, resource_name, owner_email) VALUES (?, ?, ?)`,
		resourceType, resourceName, ownerEmail,
	)
	return err
}

// Owners returns all owner identities for the given resource.
// Returns an empty slice (not an error) when no owners are registered;
// the server translates an empty slice to codes.NotFound.
func (s *OwnerStore) Owners(ctx context.Context, res *pb.Resource) ([]*pb.Identity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT owner_email FROM resource_owners WHERE resource_type = ? AND resource_name = ? ORDER BY owner_email`,
		res.GetType(), res.GetName(),
	)
	if err != nil {
		return nil, fmt.Errorf("querying owners: %w", err)
	}
	defer rows.Close()

	var owners []*pb.Identity
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, fmt.Errorf("scanning owner: %w", err)
		}
		owners = append(owners, &pb.Identity{Id: email, Name: email})
	}
	return owners, rows.Err()
}

var _ identifier.OwnerStore = (*OwnerStore)(nil)
