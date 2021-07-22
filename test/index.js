#!/usr/bin/env node

//
// ScimGateway plugin startup
// One or more plugin could be started (must be listening on unique ports)
//
// Could use forman module for running in separate environments
// PM2 module for vertical clustering/loadbalancing among cpu's'
// node-http-proxy for horizontal loadbalancing among hosts (or use nginx)
//

//const loki = require('./lib/plugin-loki')
const loki = require('./lib/plugin-mongodb')
//const restful = require('./lib/plugin-restful')
// const forwardinc  = require('./lib/plugin-forwardinc')
// const mssql = require('./lib/plugin-mssql')
// const saphana   = require('./lib/plugin-saphana')
//const api = require('./lib/plugin-api')
