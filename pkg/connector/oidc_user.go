package connector

import (
	"net/mail"
	"sort"
	"strings"

	"github.com/conductorone/baton-hashicorp-vault/pkg/client"
)

// oidcPageSize bounds the per-page N+1 entity reads: the list endpoint omits
// alias metadata, which is where OIDC claim_mappings store the email.
const oidcPageSize = 100

// emailMetadataKeys are the metadata keys checked for an email, in order.
// Vault has no native email attribute; the key is whatever the operator chose
// in the OIDC role's claim_mappings.
var emailMetadataKeys = []string{"email", "email_address", "mail"}

func isOIDCMount(mountType string) bool {
	return mountType == "oidc" || mountType == "jwt"
}

func oidcAliases(aliases []client.EntityAlias) []client.EntityAlias {
	var out []client.EntityAlias
	for _, a := range aliases {
		if isOIDCMount(a.MountType) {
			out = append(out, a)
		}
	}
	return out
}

// oidcEntityIDs returns the sorted IDs of entities that have an OIDC/JWT alias.
func oidcEntityIDs(list *client.EntityListData) []string {
	ids := make([]string, 0, len(list.KeyInfo))
	for id, info := range list.KeyInfo {
		if len(oidcAliases(info.Aliases)) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func lookupEmail(m map[string]string) string {
	for _, k := range emailMetadataKeys {
		for mk, v := range m {
			if strings.EqualFold(mk, k) {
				if e := validEmail(v); e != "" {
					return e
				}
			}
		}
	}
	return ""
}

func validEmail(s string) string {
	s = strings.TrimSpace(s)
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return ""
	}
	return s
}

// oidcEmail resolves the email for an entity from its OIDC aliases:
// alias metadata (claim_mappings), alias custom_metadata, entity metadata,
// then the alias name when the role's user_claim is email.
func oidcEmail(e *client.Entity, aliases []client.EntityAlias) string {
	for _, a := range aliases {
		if v := lookupEmail(a.Metadata); v != "" {
			return v
		}
		if v := lookupEmail(a.CustomMetadata); v != "" {
			return v
		}
	}
	if v := lookupEmail(e.Metadata); v != "" {
		return v
	}
	for _, a := range aliases {
		if v := validEmail(a.Name); v != "" {
			return v
		}
	}
	return ""
}
