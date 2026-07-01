package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RoleRepository struct {
	db *pgxpool.Pool
}

func NewRoleRepository(db *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{db: db}
}

func (repo *RoleRepository) AssignRoleByName(ctx context.Context, userID, roleName string) error {
	query := `
		INSERT INTO auth.user_roles (user_id, role_id)
		SELECT $1, id FROM auth.roles WHERE name = $2
	`

	_, err := repo.db.Exec(ctx, query, userID, roleName)
	return err
}

func (repo *RoleRepository) GetRoleNamesByUserID(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT r.name
		FROM auth.roles r
		JOIN auth.user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
	`

	rows, err := repo.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		roles = append(roles, name)
	}

	return roles, nil
}
