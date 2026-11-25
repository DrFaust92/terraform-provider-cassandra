package cassandra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gocql/gocql"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// hash returns the hex-encoded SHA-256 of s.
func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}

// cqlEscape escapes a value for use inside a single-quoted CQL string literal.
func cqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// nullIfEmpty maps "" to null. State written by the SDKv2 provider holds ""
// for optional strings that were never set; the framework expects null.
func nullIfEmpty(v types.String) types.String {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() == "" {
		return types.StringNull()
	}
	return v
}

// clusterResource holds the cluster configuration shared by all resources.
type clusterResource struct {
	cluster *gocql.ClusterConfig
}

func (r *clusterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	cluster, err := clusterFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	if cluster != nil {
		r.cluster = cluster
	}
}

// session opens a session to the cluster. Callers must close it.
func (r *clusterResource) session(diags *diag.Diagnostics) *gocql.Session {
	if r.cluster == nil {
		diags.AddError("Provider not configured", "The Cassandra provider is not configured; set host or hosts (or CASSANDRA_HOST).")
		return nil
	}
	session, err := r.cluster.CreateSession()
	if err != nil {
		diags.AddError("Unable to connect to Cassandra", fmt.Sprintf("Creating a session failed: %s", err))
		return nil
	}
	return session
}
