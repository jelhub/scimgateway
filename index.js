#!/usr/bin/env node

//
// ScimGateway plugin startup
// One or more plugin could be started (must be listening on unique ports)
//
// Could use forman module for running in separate environments
// PM2 module for vertical clustering/loadbalancing among cpu's'
// node-http-proxy for horizontal loadbalancing among hosts (or use nginx)
//

const loki = require('./lib/plugin-loki')
// const mongodb = require('./lib/plugin-mongodb')
// const scim = require('./lib/plugin-scim')
// const forwardinc = require('./lib/plugin-forwardinc')
// const mssql = require('./lib/plugin-mssql')
// const saphana = require('./lib/plugin-saphana')  // prereq: npm install hdb --save
// const azureAD = require('./lib/plugin-azure-ad')
// const ldap = require('./lib/plugin-ldap')
// const api = require('./lib/plugin-api')
