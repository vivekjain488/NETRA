# Event schema

Protocol Buffer definitions for the NETRA event model. **Phase 6.**

These are the schema of record. The transport ships JSON first, because it is
debuggable and needs no code generation step; protobuf encoding is introduced
during Phase 14 benchmarking, where a measured reduction in bytes on the wire is
worth demonstrating.

The schema is designed so new event types can be added without breaking existing
services: `event_type` is carried as a string with a validated allowlist rather
than a closed enum, so an older service tolerates an unknown type instead of
failing to decode the batch.

The current event model lives in `agent/netra-core/src/event.rs` and migration
`backend/migrations/0001_init.sql`; the `.proto` files must be generated to
match those before Phase 6 transport work begins.
