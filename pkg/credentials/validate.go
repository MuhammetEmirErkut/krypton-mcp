package credentials

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidPermission is returned when a requested privilege is not on the driver's allowlist.
var ErrInvalidPermission = errors.New("requested permission is not allowed")

// allowedSQLPrivileges is the set of table-level privileges a lease may request.
// Anything else (including multi-word strings or statement separators) is rejected so
// that caller-supplied values can never alter the shape of a generated statement.
var allowedSQLPrivileges = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "REFERENCES": true,
}

// normalizeSQLPrivileges upper-cases, de-duplicates and validates SQL privileges.
func normalizeSQLPrivileges(perms []string) ([]string, error) {
	seen := make(map[string]bool, len(perms))
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		c := strings.ToUpper(strings.TrimSpace(p))
		if !allowedSQLPrivileges[c] {
			return nil, fmt.Errorf("%w: %q", ErrInvalidPermission, p)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

var (
	redisCategoryRule = regexp.MustCompile(`^[+-]@[a-z]+$`)
	// Redis key patterns: glob characters plus a conservative set of key characters.
	redisKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_:.\-*?\[\]{}]{1,256}$`)
)

// validateRedisACLRules only accepts ACL category rules such as "+@read" or "-@dangerous".
// Rules that enable/disable the user, set passwords, or change key/channel access
// ("on", "nopass", ">pw", "~*", "allkeys", "+@all" ...) are rejected.
func validateRedisACLRules(rules []string) ([]string, error) {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if !redisCategoryRule.MatchString(r) || r == "+@all" || r == "+@admin" || r == "+@dangerous" {
			return nil, fmt.Errorf("%w: %q", ErrInvalidPermission, r)
		}
		out = append(out, r)
	}
	return out, nil
}

func validateRedisKeyPattern(p string) error {
	if !redisKeyPattern.MatchString(p) {
		return fmt.Errorf("%w: key pattern %q", ErrInvalidPermission, p)
	}
	return nil
}
