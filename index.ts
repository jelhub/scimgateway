#!/usr/bin/env bun

// for Node.js use shebang: #!/usr/bin/env -S node --import=tsx
//
// SCIM Gateway plugin startup
// One or more plugin can be started having unique port listener (configuration scimgateway.port)
//
// some plugin requires module to be installed e.g.,:
// plugin-soap: bun install soap
// plugin-mssql: bun install tedious
// plugin-saphana: bun install hdb
//

// start one or more plugins:
// import './lib/plugin-scim.ts'
// import './lib/plugin-entra-id.ts'
// import './lib/plugin-ldap.ts'
// import './lib/plugin-mongodb.ts'
// import './lib/plugin-api.ts'
// import './lib/plugin-mssql.ts'
// import './lib/plugin-saphana.ts'
// import './lib/plugin-soap.ts'

import './lib/plugin-loki.ts'
export {}
