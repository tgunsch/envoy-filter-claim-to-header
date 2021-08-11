# envoy-filter-jwt-claim-to-header

Playground of an envoy HTTP filter written as Rust Wasm plugin. The goal was to get an intro to Rust and learn something
about Wasm plugins for envoy during a multi hour train trip.

The code and deployment is based on Example https://github.com/otomato-gh/proxy-wasm-rust

## Use case

Some applications could be authorized only by setting specific header-property like `X-WEBAUTH-USER`. 
This filter offers the possibility to copy a JWT claim to a HTTP header value in the upstream request.

So the following configuration is done in [envoy.yaml](./envoy.yaml) for the demo:
* Validate an JWT, passed as Authorization Bearer token. In the demo against a static key; 
  in real life this should be done against jwks (https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter.html)
* Copy the claim `sub` to header `X-WEBAUTH-USER` (this wasm filter)
* Remove the Authorization header for security reasons (https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route.proto.html?highlight=request_headers_to_remove)

## Prerequisite

* [Rust & cargo](https://www.rust-lang.org/tools/install) 
* [docker](https://docs.docker.com/engine/install/ubuntu/) & [docker-compose](https://docs.docker.com/compose/install/)
* [Task](https://taskfile.dev) for build and deploy

## Build and run

```shell
# build the wasm plugin ./target/wasm32-unknown-unknown/release/hello_wasm.wasm
task build

# build the docker image hello_wasm_envoy:latest with includes the plugin and envoy-config
task docker-build

# deploy envoy and httpod backend with docker-compose
task start

# call with JWT
export set TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJkZW1vIn0.BnBTjKUMizZyzaRXUR0epc9fjYyFSjErvY2bw64OKLA
curl -H "Authorization: Bearer $TOKEN" http://localhost:9211/api/get

# Result:
{
   "host": "localhost:9211",
   "remote-address": "172.19.0.3:56808",
   "url": "localhost:9211/api/get",
   "args": {},
   "headers": {
      "Accept": "*/*",
      "User-Agent": "curl/7.68.0",
      "X-Envoy-Expected-Rq-Timeout-Ms": "15000",
      "X-Forwarded-Proto": "http",
      "X-Request-Id": "fa6d2e55-04b4-4798-828b-6af4547b813b",
      "X-Webauth-User": "1234567890"
   }
}         
```

The token was created on [jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJkZW1vIn0.BnBTjKUMizZyzaRXUR0epc9fjYyFSjErvY2bw64OKLA)
with payload:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "iss": "demo"
}

```
and base64 encoded secret `bXktc2VjcmV0LWtleQo=`

# Docs about Rust / proxy-wasm and envoy
* Rust book: https://doc.rust-lang.org/book/ch00-00-introduction.html
* Cargo book: https://doc.rust-lang.org/cargo/index.html
* Crate proxy-wasm: https://docs.rs/proxy-wasm/0.1.4/proxy_wasm/
* envoy http wasm filter: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter
