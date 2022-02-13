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
const scim = require('./lib/plugin-scim')
const api = require('./lib/plugin-api')
// const mongodb = require('./lib/plugin-mongodb')
