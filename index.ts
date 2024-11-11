#!/usr/bin/env bun

//
// for nodejs (version >= 22.6.0) use shebang: #!/usr/bin/env -S node --experimental-strip-types
//
// SCIM Gateway plugin startup
// One or more plugin can be started having unique port listener (configuration scimgateway.port)
//
// example starting all default plugins:
// const plugins = ['loki', 'scim', 'entra-id', 'ldap', 'mssql', 'api', 'mongodb', 'saphana', 'soap']
// 
// some plugins may require modules to be installed e.g.,:
// soap    - bun/npm install soap
// mssql   - bun/npm install tedious
// saphana - bun/npm install hdb
//

const plugins = ['loki']

for (const plugin of plugins) {
  try {
    await import(`./lib/plugin-${plugin}.ts`)
  } catch (err: any) {
    console.error(`plugin-${plugin} startup error: ${err.message}`)
    console.log()
  }
}
