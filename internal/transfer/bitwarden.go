package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-warden/v4/internal/audit"
	"github.com/go-tangra/go-tangra-warden/v4/internal/authz"
	"github.com/go-tangra/go-tangra-warden/v4/internal/folders"
	"github.com/go-tangra/go-tangra-warden/v4/internal/repo"
	"github.com/go-tangra/go-tangra-warden/v4/internal/secrets"
)

// Bitwarden document shapes (api/schema/bitwarden.schema.json).
type (
	Document struct {
		Encrypted bool     `json:"encrypted"`
		Folders   []Folder `json:"folders"`
		Items     []Item   `json:"items"`
	}
	Folder struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	Item struct {
		ID              string    `json:"id,omitempty"`
		FolderID        *string   `json:"folderId"`
		Type            int       `json:"type"`
		Name            string    `json:"name"`
		Notes           *string   `json:"notes"`
		Favorite        bool      `json:"favorite,omitempty"`
		Login           *Login    `json:"login"`
		Fields          []Field   `json:"fields,omitempty"`
		PasswordHistory []History `json:"passwordHistory,omitempty"`
	}
	Login struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
		TOTP     *string `json:"totp"`
		URIs     []URI   `json:"uris"`
	}
	URI struct {
		URI   *string `json:"uri"`
		Match *int    `json:"match"`
	}
	Field struct {
		Name  *string `json:"name"`
		Value *string `json:"value"`
		Type  *int    `json:"type"`
	}
	History struct {
		LastUsedDate string `json:"lastUsedDate,omitempty"`
		Password     string `json:"password"`
	}
)

// Strategy is the duplicate handling.
type Strategy string

// Strategies.
const (
	Skip      Strategy = "skip"
	Rename    Strategy = "rename"
	Overwrite Strategy = "overwrite"
)

// Report is the outcome of a validation or an import.
type Report struct {
	Folders     int         `json:"folders"`
	Items       int         `json:"items"`
	Created     int         `json:"created"`
	Renamed     int         `json:"renamed"`
	Skipped     int         `json:"skipped"`
	Overwritten int         `json:"overwritten"`
	Failed      int         `json:"failed"`
	Collisions  []Collision `json:"collisions"`
	Problems    []Problem   `json:"problems"`
	Warnings    []string    `json:"warnings"`
}

// Collision is an item whose name already exists in its target folder.
type Collision struct {
	Name   string `json:"name"`
	Folder string `json:"folder"`
}

// Problem is an item that cannot be imported.
type Problem struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// Service performs transfers with the folder and secret services (which
// apply permissions and audit each write).
type Service struct {
	st      repo.Store
	folders *folders.Service
	secrets *secrets.Service
	az      *authz.Authz
	audit   *audit.Writer
	now     func() time.Time
}

// New wires the service.
func New(st repo.Store, f *folders.Service, s *secrets.Service, az *authz.Authz, aw *audit.Writer) *Service {
	return &Service{st: st, folders: f, secrets: s, az: az, audit: aw, now: time.Now}
}

// ParseBitwarden decodes and checks the document shape and limits.
func ParseBitwarden(data []byte) (Document, error) {
	var doc Document
	if err := DecodeBounded(data, &doc); err != nil {
		return Document{}, err
	}
	if doc.Encrypted {
		return Document{}, fmt.Errorf("%w: encrypted exports are not accepted", ErrInvalid)
	}
	if len(doc.Items) > MaxItems || len(doc.Folders) > MaxFolders {
		return Document{}, fmt.Errorf("%w: too many items or folders", ErrInvalid)
	}
	for i, f := range doc.Folders {
		if strings.TrimSpace(f.Name) == "" || len(f.Name) > 400 || len(f.ID) > 64 {
			return Document{}, fmt.Errorf("%w: folder %d", ErrInvalid, i)
		}
	}
	return doc, nil
}

func clean(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

// mapped is an item after field mapping.
type mapped struct {
	index    int
	name     string
	folder   string // bitwarden folder path ("" = target root)
	username string
	host     string
	notes    string
	metadata map[string]any
	totp     string
	versions []string // oldest first, current last
}

func (s *Service) mapItem(i int, it Item, folderNames map[string]string, rep *Report) (mapped, bool) {
	if it.Type != 1 {
		rep.Skipped++
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("item %d (%s): type %d is not a login; skipped", i, it.Name, it.Type))
		return mapped{}, false
	}
	m := mapped{index: i, name: strings.TrimSpace(it.Name), metadata: map[string]any{}}
	fail := func(reason string) (mapped, bool) {
		rep.Problems = append(rep.Problems, Problem{Index: i, Reason: reason})
		return mapped{}, false
	}
	if m.name == "" || len(m.name) > secrets.NameMax || !clean(m.name) || strings.ContainsRune(m.name, '/') {
		return fail("invalid name")
	}
	if it.FolderID != nil && *it.FolderID != "" {
		name, ok := folderNames[*it.FolderID]
		if !ok {
			return fail("unknown folder")
		}
		m.folder = name
	}
	if it.Login != nil {
		if it.Login.Username != nil {
			m.username = *it.Login.Username
		}
		if it.Login.Password != nil {
			m.versions = append(m.versions, *it.Login.Password)
		}
		if len(it.Login.URIs) > 0 && it.Login.URIs[0].URI != nil {
			m.host = *it.Login.URIs[0].URI
		}
		if it.Login.TOTP != nil && strings.TrimSpace(*it.Login.TOTP) != "" {
			seed, err := secrets.NormalizeSeed(*it.Login.TOTP)
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("item %d (%s): totp seed not recognised; imported without it", i, m.name))
			} else {
				m.totp = seed
			}
		}
	}
	if len(m.versions) == 0 || m.versions[0] == "" {
		return fail("missing password")
	}
	if len(m.versions[0]) > secrets.PasswordMax || len(m.username) > secrets.UsernameMax || !clean(m.username) || len(m.host) > secrets.HostURLMax || !clean(m.host) {
		return fail("field too long or malformed")
	}
	if it.Notes != nil {
		m.notes = *it.Notes
		if len(m.notes) > secrets.DescriptionMax || !clean(m.notes) {
			return fail("notes too long or malformed")
		}
	}
	for _, f := range it.Fields {
		if f.Name == nil || *f.Name == "" {
			continue
		}
		v := ""
		if f.Value != nil {
			v = *f.Value
		}
		m.metadata[*f.Name] = v
	}
	if it.Favorite {
		m.metadata["favorite"] = true
	}
	if raw, _ := json.Marshal(m.metadata); len(raw) > secrets.MetadataMax {
		return fail("custom fields too large")
	}
	// History oldest first, then the current password last.
	if len(it.PasswordHistory) > 0 {
		hist := append([]History(nil), it.PasswordHistory...)
		sort.SliceStable(hist, func(a, b int) bool { return hist[a].LastUsedDate < hist[b].LastUsedDate })
		current := m.versions[0]
		m.versions = m.versions[:0]
		for _, h := range hist {
			if h.Password != "" && len(h.Password) <= secrets.PasswordMax {
				m.versions = append(m.versions, h.Password)
			}
		}
		m.versions = append(m.versions, current)
	}
	return m, true
}

// folderIndex resolves Bitwarden folder ids to slash paths.
func folderIndex(doc Document) map[string]string {
	out := map[string]string{}
	for _, f := range doc.Folders {
		parts := strings.Split(strings.Trim(strings.TrimSpace(f.Name), "/"), "/")
		var cleanParts []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" && folders.ValidName(p) {
				cleanParts = append(cleanParts, p)
			}
		}
		out[f.ID] = strings.Join(cleanParts, "/")
	}
	return out
}

// plan resolves target folders and existing names for the items.
type plan struct {
	items    []mapped
	paths    []string            // distinct bitwarden folder paths in creation order
	existing map[string]struct { // path → existing folder id (target-relative)
		id string
	}
	names map[string]map[string]string // path → lower(name) → secret id
}

func (s *Service) prepare(ctx context.Context, subj authz.Subjects, doc Document, target *string, rep *Report) (*plan, error) {
	if target != nil {
		if _, err := s.az.Require(ctx, subj, authz.Folder, *target, authz.Write); err != nil {
			return nil, err
		}
	}
	names := folderIndex(doc)
	p := &plan{names: map[string]map[string]string{}, existing: map[string]struct{ id string }{}}
	seen := map[string]bool{}
	for i, it := range doc.Items {
		m, ok := s.mapItem(i, it, names, rep)
		if !ok {
			continue
		}
		p.items = append(p.items, m)
		for path := m.folder; path != "" && !seen[path]; path = parentOf(path) {
			seen[path] = true
			p.paths = append(p.paths, path)
		}
	}
	rep.Items = len(p.items)
	sort.Slice(p.paths, func(a, b int) bool {
		return strings.Count(p.paths[a], "/") < strings.Count(p.paths[b], "/") || (strings.Count(p.paths[a], "/") == strings.Count(p.paths[b], "/") && p.paths[a] < p.paths[b])
	})
	rep.Folders = len(p.paths)
	// Existing folders under the target: walk children by name.
	byPath := map[string]string{}
	var walk func(parent *string, prefix string) error
	walk = func(parent *string, prefix string) error {
		kids, err := s.folders.Children(ctx, subj, parent)
		if err != nil {
			if errors.Is(err, authz.ErrForbidden) {
				return nil
			}
			return err
		}
		for _, k := range kids {
			path := strings.TrimPrefix(prefix+"/"+k.Name, "/")
			byPath[path] = k.ID
			if seen[path] {
				id := k.ID
				if err := walk(&id, path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(target, ""); err != nil {
		return nil, err
	}
	for path, id := range byPath {
		p.existing[path] = struct{ id string }{id}
	}
	// Existing secret names per target folder (root = target itself).
	folderIDs := map[string]*string{"": target}
	for _, path := range p.paths {
		if e, ok := p.existing[path]; ok {
			id := e.id
			folderIDs[path] = &id
		}
	}
	for path, fid := range folderIDs {
		p.names[path] = map[string]string{}
		if fid == nil && target != nil {
			continue
		}
		if fid == nil {
			// Root of the tenant: only the caller's readable root secrets matter.
			page, err := s.secrets.List(ctx, subj, nil, "", 100)
			if err != nil {
				return nil, err
			}
			for _, v := range page.Items {
				p.names[path][strings.ToLower(v.Name)] = v.ID
			}
			continue
		}
		cursor := ""
		for {
			page, err := s.secrets.List(ctx, subj, fid, cursor, 100)
			if err != nil {
				return nil, err
			}
			for _, v := range page.Items {
				p.names[path][strings.ToLower(v.Name)] = v.ID
			}
			if page.Next == "" {
				break
			}
			cursor = page.Next
		}
	}
	// Collisions: existing names and duplicates within the file.
	inFile := map[string]bool{}
	for _, m := range p.items {
		key := m.folder + "\x00" + strings.ToLower(m.name)
		if _, exists := p.names[m.folder][strings.ToLower(m.name)]; exists || inFile[key] {
			rep.Collisions = append(rep.Collisions, Collision{Name: m.name, Folder: "/" + m.folder})
		}
		inFile[key] = true
	}
	return p, nil
}

func parentOf(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i]
	}
	return ""
}

// ValidateBitwarden reports counts, collisions and problems without writing.
func (s *Service) ValidateBitwarden(ctx context.Context, subj authz.Subjects, data []byte, target *string) (Report, error) {
	rep := Report{Collisions: []Collision{}, Problems: []Problem{}, Warnings: []string{}}
	doc, err := ParseBitwarden(data)
	if err != nil {
		return rep, err
	}
	if _, err := s.prepare(ctx, subj, doc, target, &rep); err != nil {
		return rep, err
	}
	s.emit(audit.Event{Type: audit.TransferValidated, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "transfer", Outcome: "ok",
		Details: map[string]any{"items": rep.Items, "folders": rep.Folders, "collisions": len(rep.Collisions), "problems": len(rep.Problems)}})
	return rep, nil
}

// ImportBitwarden imports into the target folder with the duplicate strategy.
func (s *Service) ImportBitwarden(ctx context.Context, subj authz.Subjects, data []byte, target *string, strategy Strategy) (Report, error) {
	rep := Report{Collisions: []Collision{}, Problems: []Problem{}, Warnings: []string{}}
	switch strategy {
	case Skip, Rename, Overwrite:
	default:
		return rep, fmt.Errorf("%w: unknown duplicate strategy", ErrInvalid)
	}
	doc, err := ParseBitwarden(data)
	if err != nil {
		return rep, err
	}
	p, err := s.prepare(ctx, subj, doc, target, &rep)
	if err != nil {
		return rep, err
	}
	// Folders: create missing ones in path order (existing are reused). The
	// target and every folder created here are writable by the importer.
	ids := map[string]*string{"": target}
	writable := map[string]bool{"": true}
	for _, path := range p.paths {
		if e, ok := p.existing[path]; ok {
			id := e.id
			ids[path] = &id
			continue
		}
		parent := ids[parentOf(path)]
		name := path[strings.LastIndex(path, "/")+1:]
		f, err := s.folders.Create(ctx, subj, parent, name)
		if err != nil {
			rep.Failed++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("folder %s: %v", path, describe(err)))
			ids[path] = parent
			continue
		}
		id := f.ID
		ids[path] = &id
		writable[path] = true
		if p.names[path] == nil {
			p.names[path] = map[string]string{}
		}
	}
	for _, m := range p.items {
		folderID := ids[m.folder]
		names := p.names[m.folder]
		if names == nil {
			names = map[string]string{}
			p.names[m.folder] = names
		}
		name := m.name
		existing, collides := names[strings.ToLower(name)]
		if collides {
			switch strategy {
			case Skip:
				rep.Skipped++
				continue
			case Rename:
				for n := 2; ; n++ {
					candidate := fmt.Sprintf("%s (%d)", m.name, n)
					if _, taken := names[strings.ToLower(candidate)]; !taken {
						name = candidate
						break
					}
				}
			case Overwrite:
				if err := s.overwrite(ctx, subj, existing, m); err != nil {
					rep.Failed++
					rep.Problems = append(rep.Problems, Problem{Index: m.index, Reason: describe(err)})
					continue
				}
				rep.Overwritten++
				continue
			}
		}
		meta, _ := json.Marshal(m.metadata)
		in := secrets.Input{FolderID: folderID, Name: name, Username: m.username, HostURL: m.host, Description: m.notes, Metadata: meta, Password: m.versions[0], TOTP: m.totp, Source: "import"}
		var v secrets.View
		var err error
		if writable[m.folder] {
			v, err = s.secrets.CreateChecked(ctx, subj, in)
		} else {
			v, err = s.secrets.Create(ctx, subj, in)
		}
		if err != nil {
			rep.Failed++
			rep.Problems = append(rep.Problems, Problem{Index: m.index, Reason: describe(err)})
			continue
		}
		names[strings.ToLower(name)] = v.ID
		for _, pw := range m.versions[1:] {
			if _, err := s.secrets.UpdatePasswordFrom(ctx, subj, v.ID, pw, "", "import"); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("item %d (%s): history version not stored: %v", m.index, m.name, describe(err)))
				break
			}
		}
		if collides {
			rep.Renamed++
		} else {
			rep.Created++
		}
	}
	s.emit(audit.Event{Type: audit.TransferImported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "transfer", Outcome: "ok",
		Details: map[string]any{"strategy": string(strategy), "created": rep.Created, "renamed": rep.Renamed, "skipped": rep.Skipped, "overwritten": rep.Overwritten, "failed": rep.Failed}})
	return rep, nil
}

// overwrite updates an existing secret's metadata and adds a new version.
func (s *Service) overwrite(ctx context.Context, subj authz.Subjects, id string, m mapped) error {
	meta, _ := json.Marshal(m.metadata)
	if _, err := s.secrets.Update(ctx, subj, id, secrets.Patch{Username: &m.username, HostURL: &m.host, Description: &m.notes, Metadata: meta}); err != nil {
		return err
	}
	if _, err := s.secrets.UpdatePasswordFrom(ctx, subj, id, m.versions[len(m.versions)-1], "imported", "overwrite"); err != nil {
		return err
	}
	if m.totp != "" {
		if err := s.secrets.SetTOTP(ctx, subj, id, m.totp); err != nil {
			return err
		}
	}
	return nil
}

func describe(err error) string {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return "forbidden"
	case errors.Is(err, authz.ErrNotFound):
		return "not_found"
	case errors.Is(err, secrets.ErrVaultUnavailable):
		return "vault_unavailable"
	case errors.Is(err, folders.ErrConflict):
		return "conflict"
	case errors.Is(err, secrets.ErrInvalid), errors.Is(err, folders.ErrInvalidName), errors.Is(err, secrets.ErrInvalidTOTP):
		return "validation_failed"
	}
	return "failed"
}

// ExportBitwarden writes the readable secrets (optionally one subtree) as a
// Bitwarden document with passwords; audited once as a bulk disclosure.
func (s *Service) ExportBitwarden(ctx context.Context, subj authz.Subjects, folderID *string) (Document, error) {
	views, err := s.secrets.Readable(ctx, subj, folderID, MaxItems)
	if err != nil {
		return Document{}, err
	}
	doc := Document{Encrypted: false, Folders: []Folder{}, Items: []Item{}}
	folderIDs := map[string]string{}
	for _, v := range views {
		password, seed, err := s.secrets.MaterialOf(ctx, subj, v)
		if err != nil {
			s.emit(audit.Event{Type: audit.TransferExported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "transfer", Outcome: "failed", Reason: describe(err), Details: map[string]any{"count": len(doc.Items)}})
			return Document{}, err
		}
		it := Item{ID: v.ID, Type: 1, Name: v.Name, Login: &Login{Username: strp(v.Username), Password: strp(password)}}
		if v.HostURL != "" {
			it.Login.URIs = []URI{{URI: strp(v.HostURL)}}
		}
		if v.Description != "" {
			it.Notes = strp(v.Description)
		}
		if seed != "" {
			it.Login.TOTP = strp(seed)
		}
		var meta map[string]any
		_ = json.Unmarshal(v.Metadata, &meta)
		keys := make([]string, 0, len(meta))
		for k := range meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := fmt.Sprint(meta[k])
			it.Fields = append(it.Fields, Field{Name: strp(k), Value: strp(val)})
		}
		if v.FolderPath != "" {
			name := strings.TrimPrefix(v.FolderPath, "/")
			fid, ok := folderIDs[name]
			if !ok {
				fid = fmt.Sprintf("f%d", len(folderIDs)+1)
				folderIDs[name] = fid
				doc.Folders = append(doc.Folders, Folder{ID: fid, Name: name})
			}
			it.FolderID = strp(fid)
		}
		doc.Items = append(doc.Items, it)
	}
	s.emit(audit.Event{Type: audit.TransferExported, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "transfer", Outcome: "ok",
		Details: map[string]any{"count": len(doc.Items), "folder_id": strpv(folderID)}})
	return doc, nil
}

func strp(s string) *string { return &s }

func strpv(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
