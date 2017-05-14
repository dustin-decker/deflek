# deflEK

Reverse proxy to add index-level RBAC to Elasticsearch (soon) or Kibana

This is an early POC. It is not close to being feature complete. Use at your own risk.

It currently requires fronting with a SSO authentication proxy to pass Username and Group headers for RBAC lookup. deflEK assumes this is trusted input. If that is not true for your use case, you MUST add authentication middleware.

Features:
- whitelist indicies that can be queried in Kibana by users and groups

Desired Features:
- Kibana feature toggles (index pattern management, console, etc)
- whitelist REST verbs and indices for Elasticsearch requests
- query traces - audit log, execution time (using log15 JSON)
- request traces - auditlog, execution time (using log15 JSON)
