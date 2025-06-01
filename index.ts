#!/usr/bin/env bun

//
// for Node.js (version >= 22.6.0) use shebang: #!/usr/bin/env -S node --experimental-strip-types
//
// SCIM Gateway plugin startup
// One or more plugin can be started having unique port listener (configuration scimgateway.port)
//
// example starting all default plugins:
// const plugins = ['loki', 'scim', 'entra-id', 'ldap', 'mssql', 'api', 'mongodb', 'saphana', 'soap']
// 
// some plugin requires module to be installed e.g.,:
// plugin-soap: bun install soap
// plugin-mssql: bun install tedious
// plugin-saphana - bun install hdb
//

const plugins = ['loki']

for (const plugin of plugins) {
  try {
    await import(`./lib/plugin-${plugin}.ts`)
  } catch (err: any) {
    console.error(err)
  }
}
