# Change Log

### v6.2.8
- **[Fixed]** incorrect response headers when running in stream publisher mode.
- Dependencies bump

### v6.2.7
- **[Fixed]** When compiling scimgateway plugins to standalone binaries using `bun build --compile`, the original `saml` npm package failed at runtime on any machine other than the build machine.

### v6.2.6
- **[Fixed]** `plugin-entra-id` group members retrieval is not paginated, and members may be missing for groups with many members.
- **[Improved]** `HelperRest` updated OData pagination logic and allowing some more throttle retries.

### v6.2.5
- **[Fixed]** jwt config key `azureTenantId` not detected.

### v6.2.4
- **[Improved]** `plugin-entra-id` now support reset users MFA capabilites and user will be forced to re-register MFA.

### v6.2.3
- **[Improved]** `plugin-entra-id` now includes information on whether a user has registered for MFA (has an MFA-capable method registered).

### v6.2.2
- **[Improved]** `plugin-entra-id` now supports Entra ID IGA Access Packages. For required API permissions, see Entra ID App Registration

### v6.2.1
- `HelperRest`: fixed minor log cosmetics introduced in v6.2.0

### v6.2.0
- **[Fixed]** `HelperRest`: failed on Bun v1.3.14 due to stricter Fetch standards compliance
- **[Improved]** New `plugin-generic` replaces `plugin-scim`. Uses `endpointMapper` with the new `valueMap` option for group allowlisting and name mapping. Default config uses one-to-one SCIM mapping with plugin-loki as the target endpoint.
- **[Improved]** `endpointMapper` now supports `valueMap`:

  ```json
  "map": {
    "group": {
      "displayName": {
        "mapTo": "displayName",
        "type": "string",
        "valueMap": {
          "outboundEndpointGrp1": "inboundScimGrp1",
          "Employees": "Admins"
        }
      }
    }
  }
  ```

  Clients only see and manage the SCIM-named groups (`inboundScimGrp1`, `Admins`), mapped to their endpoint counterparts (`outboundEndpointGrp1`, `Employees`). Useful for allowlisting specific groups or supporting different inbound/outbound names.

### v6.1.20
- `plugin-entra-id`: roles introduced in v6.1.19 were missing when retrieving a single user

### v6.1.19
- **[Fixed]** SCIM v2.0 ResourceType endpoint schemas using incorrect id
- **[Improved]** `GET /Roles` and `GET /Entitlements` endpoint support, with user management via SCIM `roles` and `entitlements` attributes
- **[Improved]** `plugin-entra-id`: `entitlements` for Entra ID licenses (read-only); `roles` for Permanent and Eligible PIM roles (full management)
  - PIM Eligible roles: requires `RoleEligibilitySchedule.ReadWrite.All`
  - PIM Permanent roles: requires `RoleManagement.ReadWrite.Directory`
  - Remove `map.user.roles` if above conditions are not met
  - `skipSignInActivity` option (v6.1.17) no longer used; `signInActivity` and PIM role permissions are validated at startup

### v6.1.18
- `createUser` and `modifyUser` now return the full user object, ensuring returned data reflects what was modified even when the endpoint hasn't internally synced yet

### v6.1.17
- `plugin-entra-id`: fixed broken `filter=userName eq "user_upn"` introduced in v6.1.11 when using updated config with `map.user.signInActivity`
- `plugin-entra-id`: new option `endpoint.entity.[baseEntity].skipSignInActivity = true` to exclude `signInActivity` (requires Entra ID Premium + `AuditLog.Read.All`)

### v6.1.16
- `plugin-entra-id`: `GET /Entitlements` now uses `derivedIncludes` with full recursive expansion

### v6.1.15
- `plugin-entra-id`: fixed `filter=entitlements pr`

### v6.1.14
- Support for filter `attribute not pr`
- Dependencies bump

### v6.1.13
- `plugin-entra-id`: `signInActivity` attributes are now filterable

### v6.1.12
- Filter operator `pr` (presence) now forwarded to plugins (previously rejected)
- `plugin-entra-id`: handles `pr` filter on entitlements

### v6.1.11
- **[Fixed]** Incorrect schema generation when using `endpointMapper` (regression from v6.1.6)
- **[Improved]** New `GET /Entitlements` endpoint and `scimgateway.getEntitlements()` method
- `plugin-entra-id`: user license information via `entitlements`; remove `map.user.signInActivity` if Entra ID Premium is unavailable

### v6.1.10
- `plugin-entra-id`: group membership now includes nested (transitive) groups (`direct` and `indirect`)
- Fixed missing Docker files: `config/docker/.dockerignore` and `docker-compose-mssql.yml`

### v6.1.9
- `createUser`/`createGroup` responses now correctly include the generated ID

### v6.1.8 / v6.1.7
- Fixed incorrect masking of secrets in request info log messages
- `plugin-entra-id`: fixed edge case where `createUser` with a manager could fail

### v6.1.6
- Fixed `plugin-loki` and `plugin-mongodb` returning empty results when using extension schema attributes in search
- Auth failure due to `readOnly` now returns HTTP 405 instead of 401
- `postinstall` ensures `"type": "module"` is set in `package.json`
- `endpointMapper` now generates a custom schema; supports `"x-agent-schema"` for AI MCP tool instructions

### v6.1.5
- Complex filtering (`and`/`or`) handled by the gateway using the plugin's simple filter logic
- `modifyGroup` now returns HTTP 204 instead of 200
- New `/auth` endpoint for validating external authentication
- `plugin-entra-id`: supports `sw` (startsWith) filter

### v6.1.4
- Fixed OData paging in `plugin-entra-id` and `helper-rest` — missing users/groups/members in large directories
- Fixed incomplete group membership when paging not fully iterated

### v6.1.3
- Azure Relay: improved recovery on failure
- `plugin-ldap`: improvements for Active Directory and `objectGUID`/`mS-DS-ConsistencyGuid`
- `modifyGroup`: adding an existing member or removing a non-existent member now returns 200 OK instead of an error

### v6.1.2
- Fixed SMTP mail failure caused by an updated dependency
- Fixed `endpointMapper` when `mapTo` contained multiple comma-separated attributes including a multivalued one

### v6.1.1
- `plugin-ldap`: fixed race condition where `createUser` immediately followed by `readUser` could fail on some systems (e.g. Samba AD)
- Final info log message now includes full JSON serialization (durationMs, status, requestBody, responseBody, …)

### v6.1.0
- `tsx` included — SCIM Gateway now runs as ES module (TypeScript) in Node.js: `node --import=tsx ./index.ts`
- Simplified mandatory plugin initialization using static `import`
- `index.ts` updated to use static imports
- Bun binary builds now supported (see Single Binary Deployment)

### v6.0.0 — Major
- API method response bodies returned as-is (previously wrapped in `{ result: <content> }`) — **clients parsing responses must be updated**
- New `scimgateway.publicApi()` for unauthenticated `/pub/api` routes
- `bearerJwtAzure.tenantIdGUID` replaced by `bearerJwt.azureTenantId` — **existing configurations must be updated**

### v5.x — Previous Major Series
For v5.x change history (Bun/TypeScript migration, Azure Relay, Bulk Operations, SCIM Stream, HelperRest, Docker, email OAuth, and more), see the GitHub commit history.