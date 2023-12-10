//
// Copy plugins from original scimgateway package to current installation folder
//

const fs = require('fs')

function fsExistsSync (f) {
  try {
    fs.accessSync(f)
    return true
  } catch (e) {
    return false
  }
}

if (process.env.npm_config_scimgateway_postinstall_skip || process.env.SCIMGATEWAY_POSTINSTALL_SKIP) {
  console.info('The configuration `scimgateway_postinstall_skip` was set to true so `postinstall` activities are going to be skipped!')
  process.exit(0)
}

if (fsExistsSync('./node_modules')) process.exit(0) // global package - quit - no postinstall

if (!fsExistsSync('../../config')) fs.mkdirSync('../../config')
if (!fsExistsSync('../../config/certs')) fs.mkdirSync('../../config/certs')
if (!fsExistsSync('../../config/wsdls')) fs.mkdirSync('../../config/wsdls')
if (!fsExistsSync('../../config/schemas')) fs.mkdirSync('../../config/schemas')
if (!fsExistsSync('../../config/docker')) fs.mkdirSync('../../config/docker')
if (!fsExistsSync('../../lib')) fs.mkdirSync('../../lib')

if (!fsExistsSync('../../config/plugin-loki.json')) fs.writeFileSync('../../config/plugin-loki.json', fs.readFileSync('./config/plugin-loki.json'))
if (!fsExistsSync('../../config/plugin-scim.json')) fs.writeFileSync('../../config/plugin-scim.json', fs.readFileSync('./config/plugin-scim.json'))
if (!fsExistsSync('../../config/plugin-soap.json')) fs.writeFileSync('../../config/plugin-soap.json', fs.readFileSync('./config/plugin-soap.json'))
if (!fsExistsSync('../../config/plugin-mssql.json')) fs.writeFileSync('../../config/plugin-mssql.json', fs.readFileSync('./config/plugin-mssql.json'))
if (!fsExistsSync('../../config/plugin-saphana.json')) fs.writeFileSync('../../config/plugin-saphana.json', fs.readFileSync('./config/plugin-saphana.json'))
if (!fsExistsSync('../../config/plugin-api.json')) fs.writeFileSync('../../config/plugin-api.json', fs.readFileSync('./config/plugin-api.json'))
if (!fsExistsSync('../../config/plugin-entra-id.json')) fs.writeFileSync('../../config/plugin-entra-id.json', fs.readFileSync('./config/plugin-entra-id.json')) // keep existing
if (!fsExistsSync('../../config/plugin-ldap.json')) fs.writeFileSync('../../config/plugin-ldap.json', fs.readFileSync('./config/plugin-ldap.json'))
if (!fsExistsSync('../../config/plugin-mongodb.json')) fs.writeFileSync('../../config/plugin-mongodb.json', fs.readFileSync('./config/plugin-mongodb.json'))

fs.writeFileSync('../../lib/plugin-loki.js', fs.readFileSync('./lib/plugin-loki.js'))
fs.writeFileSync('../../lib/plugin-scim.js', fs.readFileSync('./lib/plugin-scim.js'))
fs.writeFileSync('../../lib/plugin-soap.js', fs.readFileSync('./lib/plugin-soap.js'))
fs.writeFileSync('../../lib/plugin-mssql.js', fs.readFileSync('./lib/plugin-mssql.js'))
fs.writeFileSync('../../lib/plugin-saphana.js', fs.readFileSync('./lib/plugin-saphana.js'))
fs.writeFileSync('../../lib/plugin-api.js', fs.readFileSync('./lib/plugin-api.js'))
fs.writeFileSync('../../lib/plugin-entra-id.js', fs.readFileSync('./lib/plugin-entra-id.js'))
fs.writeFileSync('../../lib/plugin-ldap.js', fs.readFileSync('./lib/plugin-ldap.js'))
fs.writeFileSync('../../lib/plugin-mongodb.js', fs.readFileSync('./lib/plugin-mongodb.js'))

if (!fsExistsSync('../../config/wsdls/GroupService.wsdl')) {
  fs.writeFileSync('../../config/wsdls/GroupService.wsdl', fs.readFileSync('./config/wsdls/GroupService.wsdl'))
}
if (!fsExistsSync('../../config/wsdls/UserService.wsdl')) {
  fs.writeFileSync('../../config/wsdls/UserService.wsdl', fs.readFileSync('./config/wsdls/UserService.wsdl'))
}

fs.writeFileSync('../../config/docker/docker-compose.yml', fs.readFileSync('./config/docker/docker-compose.yml'))
fs.writeFileSync('../../config/docker/Dockerfile', fs.readFileSync('./config/docker/Dockerfile'))
fs.writeFileSync('../../config/docker/DataDockerfile', fs.readFileSync('./config/docker/DataDockerfile'))
fs.writeFileSync('../../config/docker/docker-compose-debug.yml', fs.readFileSync('./config/docker/docker-compose-debug.yml'))

fs.writeFileSync('../../LICENSE', fs.readFileSync('./LICENSE'))
if (!fsExistsSync('../../index.js')) fs.writeFileSync('../../index.js', fs.readFileSync('./index.js'))
