package migrate3

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-warden/v4/internal/transfer"
)

// ErrActor is returned when the operator's e-mail is not in the users file.
var ErrActor = errors.New("migrate3: -actor-email is not a v4 user of the target tenant (users file)")

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Users maps a lower-cased e-mail to the v4 user UUID.
type Users map[string]string

// ParseUsers reads `email,user_uuid` lines (psql \copy … CSV). A first line
// without an e-mail and a UUID (e.g. "email,id") is taken as a header.
func ParseUsers(r io.Reader) (Users, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 2
	cr.TrimLeadingSpace = true
	u := Users{}
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return u, nil
		}
		if err != nil {
			return nil, fmt.Errorf("migrate3: users file: %w", err)
		}
		email, id := strings.ToLower(strings.TrimSpace(rec[0])), strings.ToLower(strings.TrimSpace(rec[1]))
		if !uuidRE.MatchString(id) {
			if line == 1 && !strings.Contains(email, "@") {
				continue // header
			}
			return nil, fmt.Errorf("migrate3: users file line %d: %q is not a UUID", line, rec[1])
		}
		if email == "" {
			return nil, fmt.Errorf("migrate3: users file line %d: empty e-mail", line)
		}
		if prev, ok := u[email]; ok && prev != id {
			return nil, fmt.Errorf("migrate3: users file line %d: %s maps to two users", line, email)
		}
		u[email] = id
	}
}

// RoleMap maps a v3 role (code, or the numeric id found in a permission row)
// to a v4 role string.
type RoleMap map[string]string

// ParseRoleMap reads "v3=v4,v3=v4" (e.g. "platform:admin=admin,1=admin").
func ParseRoleMap(s string) (RoleMap, error) {
	m := RoleMap{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		from, to, ok := strings.Cut(pair, "=")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" || strings.ContainsAny(to, " \t") {
			return nil, fmt.Errorf("migrate3: role map entry %q: want v3role=v4role", pair)
		}
		if _, dup := m[from]; dup {
			return nil, fmt.Errorf("migrate3: role map: %q mapped twice", from)
		}
		m[from] = to
	}
	return m, nil
}

// MappingReport lists what could not be carried over as it was.
type MappingReport struct {
	UnmappedUsers            map[string]int `json:"unmapped_users"`         // e-mail → grants skipped
	UnmappedRoles            map[string]int `json:"unmapped_roles"`         // v3 role → grants skipped
	UnknownSubjects          int            `json:"grants_without_email"`   // v3 user without an e-mail
	InvalidGrants            int            `json:"grants_invalid_subject"` // unknown subject type
	AuthorFallbacks          int            `json:"authors_attributed_to_actor"`
	ArchivedSecrets          int            `json:"archived_secrets"` // imported as ordinary secrets
	DeletedSecrets           int            `json:"deleted_secrets"`  // exported with -include-deleted; imported live
	DroppedDescriptions      int            `json:"folder_descriptions_dropped"`
	ExportChecksumMismatches int            `json:"export_checksum_mismatches"`
	ExportWarnings           []string       `json:"export_warnings"`
}

// Map turns a bundle into a v4 migration for tenantID. actorEmail must be in
// users: the operator is the audit actor and the author of every record
// whose original author has no v4 account.
func Map(b *Bundle, tenantID string, users Users, roles RoleMap, actorEmail string) (transfer.Migration, MappingReport, error) {
	rep := MappingReport{UnmappedUsers: map[string]int{}, UnmappedRoles: map[string]int{}, ExportWarnings: append([]string{}, b.Warnings...)}
	if !uuidRE.MatchString(tenantID) {
		return transfer.Migration{}, rep, fmt.Errorf("migrate3: tenant %q is not a UUID", tenantID)
	}
	actor, ok := users[strings.ToLower(strings.TrimSpace(actorEmail))]
	if !ok {
		return transfer.Migration{}, rep, ErrActor
	}
	author := func(email string) string {
		if id, ok := users[strings.ToLower(email)]; ok {
			return id
		}
		rep.AuthorFallbacks++
		return ""
	}
	m := transfer.Migration{TenantID: tenantID, ActorID: actor, Source: transfer.MigrationSource}
	for _, f := range b.Folders {
		by := author(f.CreatedBy)
		m.Folders = append(m.Folders, transfer.MigFolder{Key: f.ID, ParentKey: f.ParentID, Name: f.Name,
			CreatedAt: at(f.CreatedAt), UpdatedAt: at(f.UpdatedAt), CreatedBy: by, UpdatedBy: by})
		if f.Description != "" {
			rep.DroppedDescriptions++
		}
	}
	for _, s := range b.Secrets {
		switch s.Status {
		case "archived":
			rep.ArchivedSecrets++
		case "deleted":
			rep.DeletedSecrets++
		}
		ms := transfer.MigSecret{Key: s.ID, FolderKey: s.FolderID, Name: s.Name, Username: s.Username, HostURL: s.HostURL, Description: s.Description,
			Metadata: s.Metadata, TOTP: s.TOTPURL, CreatedAt: at(s.CreatedAt), UpdatedAt: at(s.UpdatedAt), CreatedBy: author(s.CreatedBy), UpdatedBy: author(s.UpdatedBy)}
		for _, v := range s.Versions {
			if v.ChecksumMismatch {
				rep.ExportChecksumMismatches++
			}
			ms.Versions = append(ms.Versions, transfer.MigVersion{Number: v.Version, Password: v.Password, Missing: v.Missing, Comment: v.Comment,
				Checksum: v.Checksum, CreatedAt: at(v.CreatedAt), CreatedBy: author(v.CreatedBy)})
		}
		m.Secrets = append(m.Secrets, ms)
	}
	for _, g := range b.Grants {
		mg := transfer.MigGrant{ResourceType: g.ResourceType, ResourceKey: g.ResourceID, SubjectType: g.SubjectType, Relation: g.Relation,
			ExpiresAt: g.ExpiresAt, GrantedAt: at(g.GrantedAt), GrantedBy: author(g.GrantedBy)}
		switch g.SubjectType {
		case "user":
			if g.Subject == "" {
				rep.UnknownSubjects++
				continue
			}
			id, ok := users[strings.ToLower(g.Subject)]
			if !ok {
				rep.UnmappedUsers[strings.ToLower(g.Subject)]++
				continue
			}
			mg.SubjectID = id
		case "role":
			role, ok := roles[g.Subject]
			if !ok {
				role, ok = roles[g.SubjectV3]
			}
			if !ok {
				rep.UnmappedRoles[g.Subject]++
				continue
			}
			mg.SubjectID = role
		case "tenant":
			mg.SubjectID = ""
		default:
			rep.InvalidGrants++
			continue
		}
		m.Grants = append(m.Grants, mg)
	}
	return m, rep, nil
}

func at(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}
