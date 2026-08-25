package users

import "testing"

func TestHasMember(t *testing.T) {
	s := NewStore()

	for name, tc := range map[string]struct {
		tenant, subject string
		want            bool
	}{
		"listed member":     {"northwind", "auth0|nw-001", true},
		"other tenant":      {"contoso", "auth0|co-001", true},
		"member of another": {"contoso", "auth0|nw-001", false},
		"unknown subject":   {"northwind", "auth0|nobody", false},
		"unknown tenant":    {"fabrikam", "auth0|nw-001", false},
		"empty tenant":      {"", "auth0|nw-001", false},
		"empty subject":     {"northwind", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := s.HasMember(tc.tenant, tc.subject); got != tc.want {
				t.Errorf("HasMember(%q, %q) = %v, want %v", tc.tenant, tc.subject, got, tc.want)
			}
		})
	}
}
