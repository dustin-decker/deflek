# deflEK

NOT CURRENTLY USABLE, IN THE PROCESSES OF REWRITE

Reverse proxy to add index-level RBAC to Elasticsearch.

It currently requires fronting with a SSO authentication proxy to pass Username and Group headers for RBAC lookup. deflEK assumes these headers are trusted input. If that is not true for your use case, you MUST add authentication middleware.

Features:
- RBAC on indicies that can be queries in Kibana
- RBAC on Kibana index patterns settings and api console
- Query traces - audit log, execution time, query body, index, user, groups
- Request traces - audit log execution time, errors, messages, user, groups
- JSON logging ready for indexing

Desired Features:
- Kibana feature toggles (index pattern management, console, etc)
- whitelist REST verbs and indices for Elasticsearch requests
- Elasticsearch support
