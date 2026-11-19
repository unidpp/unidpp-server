# unidpp-server

UniDPP as **one deployment**: every module of the estate — registry,
trust, log, issuer, views (lens projection), render (interop
gateway), archive (Tier C), relay (translation hub), the operator
console, and the identity surface — in one process, one port, one
data root. The REARCH consolidation
(`TODO.rearch/00-REARCH.md`).

The modules are the existing service crates, mounted **unchanged**
behind their prefixes (each crate has exported its router since the
interface-contract series). This repo adds only the composition: the
shared root surface, the union contract, the deployment discovery
document, and the federation surface.

```text
/                       the deployment discovery document
/healthz                liveness
/openapi.yaml           the union contract (the union of every module's contract)
/openapi.json           the union contract as JSON
/version                the deployment version

/registry    /trust     /log      /issuer
/views       /render    /archive  /relay
/resolver    /console   /identity /s13
/registry-jp             the optional national peer (see below)
```

Each module keeps everything it had: its golden `openapi.yaml` is
served byte-identically at `/<module>/openapi.yaml`, its own
`/healthz` and env keys under the prefix. The swagger UIs the module
crates mount at `/docs` serve in the single-module deployments; in
this deployment the nested mount's redirect lands on the root `/docs`,
which serves nothing — read the contracts directly, at
`/<module>/openapi.yaml` or in the union document. A client of one
module changes only its base URL; a client of the deployment reads
one surface.

Paths are exact: a module prefix carries no trailing slash
(`/registry`, never `/registry/`) — the same strictness axum serves
every family contract with.

## The federation surface

`/s13` serves the cross-border seam (spec clause 12.8): a foreign
verifier registers its public key, pins a governing grid policy to a
segment, sends a SIGNED request, and receives the custodian's signed
answer — an origin-sealed class answering with an attestation offer,
denial stated with its reason, never silent. The authority
counter-signs each answer's place in the per-(subject, custodian)
sequence, and the whole choreography replays from the journal alone.
The route table is documented at
[docs.unidpp.org](https://docs.unidpp.org/federation/cross-border-seam/).

The federation state reads five environment keys:

```sh
UNIDPP_S13_STATE_FILE=data/federation.journal.jsonl  # absent: in-memory
UNIDPP_S13_CUSTODIAN_ID=unidpp-custodian             # the answering node
UNIDPP_S13_CUSTODIAN_SEED=<64 hex chars>             # absent: dev seed
UNIDPP_S13_AUTHORITY_ID=unidpp-authority             # the counter-signing node
UNIDPP_S13_AUTHORITY_SEED=<64 hex chars>             # absent: dev seed
```

An absent seed derives deterministically from a fixed development
label, which keeps local runs reproducible; a production deployment
sets its own seeds, exactly as it sets the issuer's. A production
deployment also sets the state file: the journal replays on boot,
so every registration, policy, pin and signed exchange survives a
restart.

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

The operator console mounts when the deployment carries a manifest
for it (`UNIDPP_CONSOLE_MANIFEST`), and the national peer mounts when
the deployment names its journal (`UNIDPP_SERVER_JP_STATE_FILE`):
a peer is the same registry module with its own state, not a fork.

## Tests

```sh
cargo test
cargo test -- --ignored export_golden   # regenerate tests/union-golden.yaml
```

The gates: every module answers behind its prefix; every module's
served contract equals its repo golden byte-identically; the union
document equals its committed golden; the discovery document names
exactly the mounted modules; and the federation journey passes end
to end — a foreign signed request answered, verified, journaled,
replayed and counter-signed in-process. CI checks out the family,
because the path deps (and the embedded goldens) are the siblings.
