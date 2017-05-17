# deflEK

Reverse proxy to add index-level RBAC to Elasticsearch (soon) or Kibana

This is an early POC. It is not close to being feature complete. Use at your own risk.

It currently requires fronting with a SSO authentication proxy to pass Username and Group headers for RBAC lookup. deflEK assumes these headers are trusted input. If that is not true for your use case, you MUST add authentication middleware.

Features:
- RBAC on indicies that can be queries in Kibana

Desired Features:
- Kibana feature toggles (index pattern management, console, etc)
- whitelist REST verbs and indices for Elasticsearch requests
- query traces - audit log, execution time (using log15 JSON)
- request traces - audit log, execution time (using log15 JSON)
