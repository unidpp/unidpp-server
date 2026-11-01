# unidpp-server

UniDPP as **one deployment**: every module of the estate — registry,
trust, log, issuer, views (lens projection), render (interop
gateway), archive (Tier C), relay (translation hub) — in one process,
one port, one data root. The REARCH consolidation
(`TODO.rearch/00-REARCH.md`).

The modules are the existing service crates, mounted **unchanged**
behind their prefixes (each crate has exported its router since the
interface-contract series). This repo adds only the composition: the
shared root surface, the union contract, and the deployment
discovery document.

```text
/                       the deployment discovery document
/healthz                liveness
/openapi.yaml           the union contract (one surface, eight groups)
/openapi.json           the union contract as JSON
/version                the deployment version

/registry   /trust   /log   /issuer
/views      /render  /archive   /relay
```

Each module keeps everything it had: its golden `openapi.yaml` is
served byte-identically at `/<module>/openapi.yaml`, its own
`/healthz`, `/docs` and env keys under the prefix. A client of one
module changes only its base URL; a client of the deployment reads
one surface.

Paths are exact: a module prefix carries no trailing slash
(`/registry`, never `/registry/`) — the same strictness axum serves
every family contract with.

## Run

```sh
cargo build --release
UNIDPP_SERVER_BIND=127.0.0.1:8090 ./target/release/unidpp-server
```

Every module reads its own `UNIDPP_<MODULE>_*` keys as before (the
env contract is the union, stated in the served contract document).
The runner sets the state keys under one data root and points every
inter-module `UNIDPP_*_URL` at the shared origin:

```sh
UNIDPP_REGISTRY_URL=http://127.0.0.1:8090/registry
UNIDPP_ISSUER_URL=http://127.0.0.1:8090/issuer
UNIDPP_ISSUER_REGISTRY_URL=http://127.0.0.1:8090/registry
UNIDPP_LOG_URL=http://127.0.0.1:8090/log
```

## Tests

```sh
cargo test
cargo test -- --ignored export_golden   # regenerate tests/union-golden.yaml
```

The gates: every module answers behind its prefix; every module's
served contract equals its repo golden byte-identically; the union
document equals its committed golden; the discovery document names
exactly the mounted modules. CI checks out the family, because the
path deps (and the embedded goldens) are the siblings.
