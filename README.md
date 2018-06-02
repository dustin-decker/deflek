# deflEK

Reverse proxy that adds index-level RBAC to Elasticsearch.

[![Travis CI Build Status](https://travis-ci.com/dustin-decker/deflek.svg?branch=master)](https://travis-ci.com/dustin-decker/deflek)

## Disclaimer

Deflek man-in-the-middles requests to elasticsearch in order to apply a best effort to filter access
and mutate requests to be compatible, and to provide an audit log. It is not perfect, and probably never will be. Elasticsearch needs security to be baked in to do it properly. There are solutions that come closer to this,
like [ReadOnlyREST](https://github.com/sscarduzio/elasticsearch-readonlyrest-plugin), [Search Guard](https://github.com/floragunncom/search-guard) or Elastic's own [X-pack security](https://www.elastic.co/guide/en/x-pack/current/xpack-security.html), but all of those are also bolt-on security, in
the form of an Elasticsearch plugin. So use it at your own risk! Help make it better! Make a PR to add proper RBAC
to the core of Elasticsearch!

## Authentication

It currently requires fronting with a SSO authentication proxy (such as [saml-proxy](https://github.com/dustin-decker/saml-proxy)) to pass Username and Group headers for RBAC lookup. deflEK assumes these headers are trusted input. If that is not true for your use case, you MUST add your own authentication middleware, or else it will not work.

An example setup looks like this:

`USER -> saml-proxy -> Kibana -> deflek -> Elasticsearch`

To have Kibana pass user and group headers from `saml-proxy` to `deflek`, use Kibana's `elasticsearch.requestHeadersWhitelist` configuration option, documented here: https://www.elastic.co/guide/en/kibana/6.2/settings.html
The headers specified in `config.example.yaml` would be specified like this:

```
elasticsearch.requestHeadersWhitelist: ["X-Remote-Groups", "X-Remote-User"]
```

## Features

- RBAC on indices and APIs
- Request traces - elasped time, query, errors, user, groups, indices, response code
- JSON logging, ready for indexing

## Coverage

deflek can enforce RBAC on HTTP methods for every HTTP API elasticsearch offers

aditionally, deflek has index awareness for the following APIs:

- _mget
- _msearch
- _all
- _search
- direct index access (/< index >/1)

deflek can also mutate wildcard requests on the fly, to support software like Kibana.

## Configuration

`config.example.yaml` is included as a sample configuration file. This is also the config that should be used with integration tests. It includes the indices and API whitelisting necessary to support Kibana.

You will need to edit the headers to match what your authentication layer passes to deflek. You will also need to modify groups access to match what will be included via those headers.

## Running it

Build docker image:

``` bash
docker build -t deflek .
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