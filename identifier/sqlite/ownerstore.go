package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/accretional/proto-resource/identifier"
	"github.com/accretional/proto-resource/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS resource_owners (
    resource_type TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    owner_email   TEXT NOT NULL,
    PRIMARY KEY (resource_type, resource_name)
);`

// OwnerStore is a SQLite-backed implementation of identifier.OwnerStore.
//
// Each row maps a (resource_type, resource_name) pair to an owner email.
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

// Register associates a resource (type+name) with an owner email.
// Calling Register again for the same resource replaces the existing owner.
func (s *OwnerStore) Register(ctx context.Context, resourceType, resourceName, ownerEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO resource_owners (resource_type, resource_name, owner_email) VALUES (?, ?, ?)`,
		resourceType, resourceName, ownerEmail,
	)
	return err
}

// Identify returns an Identity whose Id and Name are the owner email of the
// given resource. Returns codes.NotFound if no owner is registered.
func (s *OwnerStore) Identify(ctx context.Context, res *pb.Resource) (*pb.Identity, error) {
	var email string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner_email FROM resource_owners WHERE resource_type = ? AND resource_name = ?`,
		res.GetType(), res.GetName(),
	).Scan(&email)
	if err == sql.ErrNoRows {
		return nil, status.Errorf(codes.NotFound, "no owner for %s/%s", res.GetType(), res.GetName())
	}
	if err != nil {
		return nil, fmt.Errorf("querying owner: %w", err)
	}
	return &pb.Identity{Id: email, Name: email}, nil
}

var _ identifier.OwnerStore = (*OwnerStore)(nil)
