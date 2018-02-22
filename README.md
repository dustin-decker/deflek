# deflEK

NOT CURRENTLY USABLE, IN THE PROCESSES OF REWRITE

Reverse proxy that adds index-level RBAC to Elasticsearch.

## Authentication

It currently requires fronting with a SSO authentication proxy (such as [saml-proxy](https://github.com/dustin-decker/saml-proxy)) to pass Username and Group headers for RBAC lookup. deflEK assumes these headers are trusted input. If that is not true for your use case, you MUST add your own authentication middleware, or else it will not work.

## Features

- RBAC on indices
- Request traces - elasped time, query, errors, user, groups, indices, response code
- JSON logging, ready for indexing

## Running it

Build docker image:

``` bash
docker build -t deflek -f Dockerfile.local .
```

Deploy test stack to local Swarm:

``` bash
docker stack deploy -c docker-compose.test.yml deflek
```

## Testing it

Ensure you have the dependencies:

``` bash
dep ensure
```

Use the example config:

``` bash
cp config.example.yaml config.yaml
```

Run a test elasticsearch cluster, if needed:

``` bash
docker run -p 127.0.0.1:9200:9200 --rm -it -e "discovery.type=single-node" -v esdata1:/usr/share/elasticsearch/data docker.elastic.co/elasticsearch/elasticsearch-oss:6.2.1
```

Build and run deflek:

``` bash
go build; ./deflEK
```

Run deflek integration and unit tests:

``` bash
go test
```