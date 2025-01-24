#!/usr/bin/env bash

set -exo pipefail

 # CI test for use with CI freshservice account
if [ -z "$BATON_HCP" ]; then
  echo "BATON_HCP not set. using baton-hashicorp-vault"
  BATON_HCP=baton-hashicorp-vault
fi
if [ -z "$BATON" ]; then
  echo "BATON not set. using baton"
  BATON=baton
fi

# Error on unbound variables now that we've set BATON & BATON_HCP
set -u

# Sync
$BATON_HCP

# Grant entitlement
$BATON_HCP --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Check for grant before revoking
$BATON_HCP
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" )"

# Grant already-granted entitlement
$BATON_HCP --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Get grant ID
BATON_GRANT=$($BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --raw-output --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" ).grant.id")

# Revoke grant
$BATON_HCP --revoke-grant="$BATON_GRANT"

# Revoke already-revoked grant
$BATON_HCP --revoke-grant="$BATON_GRANT"

# Check grant was revoked
$BATON_HCP
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status "if .grants then [ .grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" ) ] | length == 0 else . end"

# Re-grant entitlement
$BATON_HCP --grant-entitlement="$BATON_ENTITLEMENT" --grant-principal="$BATON_PRINCIPAL" --grant-principal-type="$BATON_PRINCIPAL_TYPE"

# Check grant was re-granted
$BATON_HCP
$BATON grants --entitlement="$BATON_ENTITLEMENT" --output-format=json | jq --exit-status ".grants[] | select( .principal.id.resource == \"$BATON_PRINCIPAL\" )"
