# baton-connector-read
#
# Read-only Vault policy for the ConductorOne baton-hashicorp-vault connector.
# The connector reads auth methods, secret engines, policies, identity
# entities and groups, and AppRole role definitions. It only ever LISTs
# secret key names. Nothing in this file grants read on secret data.
#
# Apply it in the namespace the connector targets (--vault-namespace /
# BATON_VAULT_NAMESPACE). Policies and AppRoles are namespace-scoped, so the
# policy, the AppRole and the connector must all use the same namespace. On
# HCP Vault Dedicated the top-level namespace is "admin". For example:
#
#   vault policy write -namespace=admin/<child> baton-connector-read docs/baton-connector-read.hcl
#   vault write -namespace=admin/<child> auth/approle/role/baton-connector \
#       token_policies="baton-connector-read" token_ttl=1h token_max_ttl=4h
#
# Before every sync the connector calls auth/token/lookup-self and
# sys/capabilities-self and logs one warning per resource type it cannot
# read, naming the path, the missing capability and the namespace. Check the
# connector log after the first sync to confirm this policy reached the token.
#
# Vault evaluates LIST requests against the path both with and without a
# trailing slash, so list rules below are written without one.

# --- Token self-inspection ---------------------------------------------------
# Both are normally granted by Vault's built-in "default" policy. They are
# listed explicitly so validation keeps working for roles created with
# token_no_default_policy=true.

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}

# --- Policies ----------------------------------------------------------------
# The connector lists policies through sys/policies/acl and falls back to the
# legacy sys/policy endpoint. Either rule on its own is enough; both are
# granted so the modern endpoint is the one used.

path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policy" {
  capabilities = ["read"]
}

# --- Auth methods and secret engines -----------------------------------------
# GET sys/auth lists every auth method. Do not add sys/auth/<mount> rules:
# reading a single mount there requires sudo, and the connector never does it.
# GET sys/mounts is how the connector discovers KV engines and their versions.

path "sys/auth" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

# --- Identity ----------------------------------------------------------------
# Entities are whatever authenticated, not people: an EC2 instance that logs
# in through more than one auth mount is more than one entity, a Kubernetes
# service account is an entity, an Okta login is an entity. Groups of type
# "external" are the IdP groups (for example Okta groups) Vault learned about
# at login, and the policies attached to them are how humans receive access.
# Reading a group or entity returns its policies, aliases and members; it
# never returns credentials.

path "identity/entity/id" {
  capabilities = ["list"]
}

path "identity/entity/id/*" {
  capabilities = ["read"]
}

path "identity/group/id" {
  capabilities = ["list"]
}

path "identity/group/id/*" {
  capabilities = ["read"]
}

# --- Auth-backend roles ------------------------------------------------------
# Role definitions map an external identity (an Okta group claim on an OIDC
# or JWT mount, an AWS IAM role, a Kubernetes service account, an AppRole) to
# token_policies. The connector lists AppRole roles today. "+" matches exactly
# one path segment, so the same two rules already cover auth/oidc/role,
# auth/jwt/role, auth/aws/role, auth/kubernetes/role and any other mount that
# uses the "role" convention, should the connector start reading those.
# Reading an AppRole role exposes its role_id but not its secret_id. Listing
# or generating secret_ids would need "list" and "update" under
# auth/approle/role/<name>/secret-id, which are not granted.

path "auth/+/role" {
  capabilities = ["list"]
}

path "auth/+/role/*" {
  capabilities = ["read"]
}

# --- Secret key names --------------------------------------------------------
# One rule per KV engine the connector should enumerate. KV v2 engines list
# under <mount>/metadata; KV v1 engines list under <mount>. A mount without a
# rule is skipped with a warning. Never grant <mount>/data/*: that is secret
# data, and the connector does not read it.

path "kv/metadata/*" {
  capabilities = ["list"]
}

# Example for a KV v1 engine mounted at "legacy/":
#
# path "legacy/*" {
#   capabilities = ["list"]
# }

# --- Optional: userpass accounts ---------------------------------------------
# Only relevant if the userpass auth method is mounted in this namespace. The
# connector then reports its accounts and the policies attached to each.
# Leave this out where humans authenticate through an identity provider; the
# connector logs that the mount is absent and syncs the user type as empty.
#
# path "auth/userpass/users" {
#   capabilities = ["list"]
# }
#
# path "auth/userpass/users/*" {
#   capabilities = ["read"]
# }

# --- Optional: provisioning --------------------------------------------------
# Assigning policies to userpass accounts from ConductorOne
# (BATON_PROVISIONING=true) additionally needs update on those accounts. It
# is not part of the read-only role and should stay off unless intended.
#
# path "auth/userpass/users/*" {
#   capabilities = ["read", "update"]
# }
