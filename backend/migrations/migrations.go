// Package migrations embeds the NETRA SQL schema migrations.
//
// They are embedded in the binary so that a deployment is a single artefact
// and the schema cannot drift from the code that expects it — which also
// matters for the air-gapped deployments in spec §35.
package migrations

import "embed"

// FS holds every migration file, applied in filename order.
//
//go:embed *.sql
var FS embed.FS
