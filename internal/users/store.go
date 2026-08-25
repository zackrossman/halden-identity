// Package users serves the user directory. Auth0 is the source of truth for
// users; this store holds the Halden-side profile records keyed by Auth0 subject.
package users

// User is a Halden profile record for an Auth0 user.
type User struct {
	Subject  string `json:"subject"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
}

// Store is an in-memory user directory partitioned by tenant.
type Store struct {
	byTenant map[string][]User
}

// NewStore returns a store seeded with the current directory contents.
func NewStore() *Store {
	return &Store{byTenant: map[string][]User{
		"northwind": {
			{Subject: "auth0|nw-001", Email: "ida.brekke@northwind.example", Name: "Ida Brekke", Role: "owner", TenantID: "northwind"},
			{Subject: "auth0|nw-002", Email: "olav.sund@northwind.example", Name: "Olav Sund", Role: "operator", TenantID: "northwind"},
			{Subject: "auth0|nw-003", Email: "mari.holt@northwind.example", Name: "Mari Holt", Role: "viewer", TenantID: "northwind"},
		},
		"contoso": {
			{Subject: "auth0|co-001", Email: "dana.ortiz@contoso.example", Name: "Dana Ortiz", Role: "owner", TenantID: "contoso"},
			{Subject: "auth0|co-002", Email: "sam.whittle@contoso.example", Name: "Sam Whittle", Role: "operator", TenantID: "contoso"},
		},
	}}
}

// ListByTenant returns the users belonging to one tenant.
func (s *Store) ListByTenant(tenantID string) []User {
	users := s.byTenant[tenantID]
	out := make([]User, len(users))
	copy(out, users)
	return out
}

// HasMember reports whether a subject belongs to a tenant.
//
// This is the directory's answer to an authorization question, kept separate
// from Find so the auth package can ask it without depending on the user
// model. The directory is the authority: a subject it does not list is not a
// member, whatever the caller's token claims.
func (s *Store) HasMember(tenantID, subject string) bool {
	_, ok := s.Find(tenantID, subject)
	return ok
}

// Find returns the profile for one subject within a tenant.
func (s *Store) Find(tenantID, subject string) (User, bool) {
	for _, u := range s.byTenant[tenantID] {
		if u.Subject == subject {
			return u, true
		}
	}
	return User{}, false
}
