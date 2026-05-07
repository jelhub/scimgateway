# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Architecture

SCIM Gateway is a plugin-based REST API gateway implementing SCIM 1.1 and 2.0 for user/group provisioning. It translates incoming SCIM requests into endpoint-specific calls.

**Request flow:**

```
SCIM client → ScimGateway (HTTP server, auth, routing) → plugin method (endpoint logic) → destination system
```

### Core classes

- **`lib/scimgateway.ts`** — The central class. Plugins instantiate it, and it handles the HTTP server, request routing, authentication (Basic, Bearer JWT, OAuth, PassThrough), IP allowlisting, and SCIM format translation. Plugins implement named methods (`getUsers`, `createUser`, `modifyUser`, `deleteUser`, `getGroups`, etc.) that ScimGateway calls.

- **`lib/helper-rest.ts`** — REST client used by plugins to talk to their endpoints. Handles all auth methods, proxy, token caching.

- **`lib/logger.ts`** — Multi-output logger (console + file + remote). Log methods: `this.logger.debug/info/warn/error(baseEntity, 'message')`.

- **`lib/utils-scim.ts`** — SCIM conversion utilities: v1.1↔v2.0 attribute mapping, multi-value type-object conversion, schema loading, filter parsing.

- **`lib/utils.ts`** — General utilities: `Lock` class for mutual exclusion, encryption/decryption of config secrets.

### Plugin system

Each plugin file (e.g. `lib/plugin-loki.ts`) instantiates `ScimGateway` and implements the endpoint-specific methods. Plugins are selected by importing them in `index.ts`. Configuration is loaded from matching `config/plugin-xxx.json`.

Included plugins: `plugin-loki` (in-memory LokiJS, for demo/testing), `plugin-entra-id`, `plugin-ldap`, `plugin-mongodb`, `plugin-mssql`, `plugin-saphana`, `plugin-soap`, `plugin-scim` (SCIM-to-SCIM version gateway), `plugin-api` (generic REST).

### Multi-tenancy

All plugin methods receive a `baseEntity` parameter that selects which tenant/endpoint config section to use. The `ctx` parameter can carry passthrough auth headers.

### Multi-value attributes

Two formats exist, controlled by `scim.skipTypeConvert` in config:
- Standard SCIM: `{ "emails": [{"value": "a@b.com", "type": "work"}] }`
- Type-converted (default): `{ "emails": { "work": { "value": "a@b.com", "type": "work" } } }`

### Error conventions

Errors encode HTTP status codes in `err.name`:
```typescript
err.name = 'User already exists#409'
```

## Tests

Test files live in `test/lib/`. The test suite uses Bun's built-in test framework (`describe`, `test`, `expect`). Tests make real HTTP calls to a running gateway instance — they are integration tests, not unit tests.

Default test credentials: `gwadmin:password` (Basic auth), test users `bjensen` / `jsmith` pre-seeded in Loki.

## Config

Each plugin reads `config/plugin-xxx.json`. Secrets in config are encrypted at startup via `utils.ts`. Config supports multiple auth methods simultaneously and CIDR-based IP allowlisting.
