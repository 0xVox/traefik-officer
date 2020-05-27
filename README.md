# Traefik Officer
A small Go library designed to enable endpoint level prometheus metrics from requests logged in Traefik's access logs.

## Config

### Command Line Arguments:

- `--log-file` - Point at your traefik access log.
- `--include-query-args` - Decide whether or not to split requests to a specific endpoint into separate metrics based on the arguments passed in the URL. Not reccomended.
- `--config-file` - Point towards a json config file to configure ignored patterns. Read on for more info.
- `--listen-port` - Which port to serve metrics on. Suggest combining with [this metrics merger](https://github.com/rebuy-de/exporter-merger) to enable receiving metrics from both Traefik and Traefik officer.

### Config File
The config file is used to define things that should be ignored by the metrics publisher. An example of such a config file:
```
{
    "IgnoredNamespaces": [
        "/^-$/",
        "test"
    ],
    "IgnoredRouters": [
        "website",
        "api@internal",
        "prometheus@internal",
        "http-to-443@internal"
    ],
    "IgnoredPathsRegex": [
        "\/images\/"
    ]
}
```

The ignore function will check in the order:
- Namespaces
- Routers
- Path Regex

All matching options compile down to Golang Regex before being checked for a match. It's important that you escape any special characters. You can test regex for golang [here](https://regex101.com/) with flavor set to Golang.

#### Ignored Namespaces
There is a special value here; `-`. This is what the router name is set to for requests directly to the i.p. of the traefik instance with no host name / SNI. Note the strict regex here - since most routers contain a `-` somewhere in their name, due to the convention below.

Some internal routers can be seen to be blocked in the above example.

Router names (When run using kubernetesCRD config) take the format:
    `namespace-ingressroutename-hash@kubernetescrd`


If a request came through to the router `prod-api-hash@kubernetescrd` - it would be reported on - so long as there were no instances of `/images/` in the request path.
In this example, the router is an IngressRoute called `api` in the `prod` kubernetes namespace.

#### Ignored Routers
If you wish to block certain routers in a namespace, but not all, it is necesary to match them here.

For example, we have `api` in the ignored routers, if this were in the prod namespace - requests through the `api` IngressRoute in the `prod` namespace would be blocked. 

The matching code just runs a "Contains" check on these routers, so be specific if you have multiple IngressRoutes that contain the string `api`. 

#### Ignored Path
This is for more granular control over which endpoints in a service get reported on. In our example above we ignore any that match the regex pattern `/images/`. 

### Examples

Check the example folder, there is:
- An example kubernetes deployment YAML
- An example Grafana dashboard

