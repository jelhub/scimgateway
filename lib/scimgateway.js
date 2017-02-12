//=================================================================================
// File:    scimgateway.js
//
// Author:  Jarle Elshaug
//
// Purpose: Started by endpoint plugin
//          Listens and replies on incoming SCIM requests
//          Communicates with plugin using event callback
//=================================================================================

'use strict';

var http = require('http');
var https = require('https');
var express = require('express');
var EventEmitter = require('events').EventEmitter;
var dot = require('dot-object');
var util = require('util');
var fs = require('fs');
var path = require('path')
var callsite = require('callsite');
var utils = require("../lib/utils");

/**
 * @constructor
 */
var ScimGateway = function () {

    var stack = callsite();
    var requester = stack[1].getFileName();
    var pluginName = path.basename(requester, '.js');
    var dirConfig = path.dirname(requester) + '/../config';
    var configFile = `${dirConfig}/${pluginName}.json`; // config name prefix same as pluging name prefix
    var config = require(configFile).scimgateway;
    var gwName = path.basename(__filename, '.js'); // prefix of current file 
    var dirLogs = path.dirname(requester) + '/../logs';
    var log = require('../lib/logger')(config.loglevel, `${dirLogs}/${pluginName}.log`);
    var logger = log.logger;
    this.logger = logger;                           // exposed to plugin-code
    this.notValidAttributes = notValidAttributes;   // exposed to plugin-code

    // verify configuration file - scimgateway sub-elements
    if (!isValidconfig(config, ["localhostonly", "port", "username", "password", "loglevel"])) {
        logger.error(`${gwName} Configurationfile: ${require.resolve(configFile)}`);
        logger.error(`${gwName} Configurationfile have wrong or missing scimgateway sub-elements`);
        logger.error(`${gwName} Stopping...`);
        console.log();
        // process.exit(1) // may miss unflushed logger updates to logfile
        throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'));
    }
    var gwPassword = ScimGateway.prototype.getPassword('scimgateway.password', configFile);
    if (!gwPassword) {
        logger.error(`${gwName} Scimgateway password decryption failed`);
        logger.error(`${gwName} Stopping...`);
        console.log();
        // process.exit(1) // may miss unflushed logger updates to logfile
        throw (new Error('Using exception to stop further asynchronous code execution (ensure synchronous logger flush to logfile and exit program), please ignore this one...'));
    }
    if (!fs.existsSync(dirLogs)) fs.mkdirSync(dirLogs);
    if (!fs.existsSync(dirConfig + '/wsdls')) fs.mkdirSync(dirConfig + '/wsdls')
    if (!fs.existsSync(dirConfig + '/certs')) fs.mkdirSync(dirConfig + '/certs')

    var scimDef = null;
    if (config.scimversion && config.scimversion === "2.0") scimDef = require('../lib/scimdef-v2');
    else scimDef = require('../lib/scimdef-v1');
    this.testmodeusers = scimDef.TestmodeUsers.Resources; // exported and used by plugin-testmode
    this.testmodegroups = scimDef.TestmodeGroups.Resources; // exported and used by plugin-testmode
    var errMsg = '';
    var app = express();
    var basicAuth = require('basic-auth');

    app.disable('etag'); // no etag header - disable local browser caching of headers - content type header changes will then be reflected
    app.disable('x-powered-by'); // no nodejs-express information in header
    app.use(function (req, res, next) { // authentication & content type
        var user = basicAuth(req)
        if (!user || user.name !== config.username || user.pass !== gwPassword) {
            if (user) logger.error(`${gwName} authentication failed for user "${user.name}"`);
            res.setHeader('WWW-Authenticate', 'Basic realm="ScimGateway"');
            res.status(401).end('Access denied');
        } else {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            return next();
        }
    });
    app.use(require('morgan')('combined', { "stream": log.stream }));   // express logging to log.stream (combined/common) instead of: app.use(express.logger('dev'));  /* 'default', 'short', 'tiny', 'dev' */


    // Initial connection, step #1: GET /ServiceProviderConfigs
    // If not included => Provisioning will always use GET /Users without any paramenters
    app.get('(|/:baseEntity)/ServiceProviderConfigs', function (req, res) {
        var tx = scimDef.ServiceProviderConfigs; // obfuscator friendly
        res.send(tx);
        logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`);
    });


    // Initial connection, step #2: GET /Schemas
    app.get('(|/:baseEntity)/Schemas', function (req, res) {
        var tx = scimDef.Schemas;
        res.send(tx);
        logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`);
    });


    app.get('(|/:baseEntity)/Schemas/Users', function (req, res) {
        var tx = scimDef.Schemas.Resources[0];
        res.send(tx);
        logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`);
    });


    app.get('(|/:baseEntity)/Schemas/Groups', function (req, res) {
        var tx = scimDef.Schemas.Resources[0];
        res.send(tx);
        logger.debug(`${gwName} GET = ${req.originalUrl} Response = ${JSON.stringify(tx)}`);
    });


    app.get('(|/:baseEntity)/Users', (req, res) => {
        if (req.query.attributes === 'userName' && !req.query.filter) {
            //==========================================
            //             EXPLORE USERS
            //==========================================
            //
            // GET /Users?attributes=userName&startIndex=1&count=100
            //
            logger.debug(`${gwName} [Explore Users]`);
            var scimdata = new scimDef.scimResource();
            logger.debug(`${gwName} emitting event "exploreUsers" and awaiting result`);
            this.emit('exploreUsers', req.params.baseEntity, req.query.startIndex, req.query.count, function (err, data) {
                if (err) {
                    if (!err.message) err['message'] = JSON.stringify(err);
                    logger.error(`${gwName}[${pluginName}] ${err.message}`);
                    res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                }
                else {
                    if (data) scimdata = data;
                    scimdata = addPagination(scimdata, req.query.startIndex);
                    res.send(scimdata);
                    logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                }
            });


        } else if (req.query.filter) {
            //==========================================
            //             GET USER
            //==========================================
            //
            // GET /Users?filter=userName eq "bjensen"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements
            //
            // Get user request before/after updating a user:
            // GET = /Users?filter=userName eq "jsmith"&attributes=id,userName
            //
            //Get user request for retreving all attributes:
            //GET = /Users?filter=userName eq "jsmith"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements
            //
            //  ---- retreive all users for a spesific group ----
            //
            // "user member of group" => CA IM default scim endpoint config - Group having multivalue attribute members containing userName
            // GET = /Users?filter=id eq "jsmith"&attributes=id,userName
            // 
            // "group member of user" => User having multivalue attribute groups containing value=GroupName
            // GET = /Users?filter=groups.value eq "UserGroup-1"&attributes=groups.value,userName
            //
            var arrFilter = req.query.filter.split(" "); // userName eq "bjensen"
            if (arrFilter.length > 2) {
                if ((arrFilter[0] === 'userName' || arrFilter[0] === 'id') && arrFilter[1] === 'eq') {
                    var userName = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, ''); // bjensen
                    logger.debug(`${gwName} [Get User] userName=${userName}`);
                    var scimdata = new scimDef.scimResource();
                    logger.debug(`${gwName} emitting event "getUser" and awaiting result`);
                    this.emit('getUser', req.params.baseEntity, userName, req.query.attributes, function (err, data) {
                        if (err) {
                            if (!err.message) err['message'] = JSON.stringify(err);
                            logger.error(`${gwName}[${pluginName}] ${err.message}`);
                            res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                        }
                        else {
                            if (data) scimdata.Resources.push(data);
                            scimdata = addPagination(scimdata, undefined);
                            res.send(scimdata);
                            logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                        }
                    });
                }
                else if ((arrFilter[0] === 'groups.value') && arrFilter[1] === 'eq') {
                    // retreive all users for a spesific group - "group member of user" - using groups attribute on user
                    var groupName = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, '');// UserGroup-1
                    logger.debug(`${gwName} [Get User] group=${groupName}`);
                    var scimdata = new scimDef.scimResource();
                    logger.debug(`${gwName} emitting event "getGroupUsers" and awaiting result`);
                    this.emit('getGroupUsers', req.params.baseEntity, groupName, req.query.attributes, function (err, data) {
                        if (err) {
                            if (!err.message) err['message'] = JSON.stringify(err);
                            logger.error(`${gwName}[${pluginName}] ${err.message}`);
                            res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                        }
                        else {
                            //if (data) scimdata.Resources.push(data);
                            if (data) scimdata.Resources = data;
                            scimdata = addPagination(scimdata, undefined);
                            res.send(scimdata);
                            logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                        }
                    });

                }
                else {
                    errMsg = 'GET /Users?filter="<Incorrect filter definition>" must include userName (or id) and eq';
                    res.status(400).send(`ScimGateway ${gwName} ${errMsg}`);
                    logger.error(`${gwName} GET = ${req.originalUrl} Response = ${errMsg}`);
                }
            } else {
                errMsg = '"GET /Users?filter="<Incorrect filter definition>"';
                res.status(400).send(`ScimGateway ${gwName} ${errMsg}`);
                logger.error(`${gwName} GET = ${req.originalUrl} Response = ${errMsg}`);
            }

        } else {
            // GET /Users
            errMsg = `GET "${req.originalUrl}" is not supported`;
            res.status(400).send(`ScimGateway ${gwName} ${errMsg}`);
            logger.error(`${gwName} GET = ${req.originalUrl} Response = ${errMsg}`);
        }
    });


    app.get('(|/:baseEntity)/Groups', (req, res) => {
        var scimdata = new scimDef.scimResource();
        if (req.query.attributes == 'displayName' && !req.query.filter) {
            //==========================================
            //             EXPLORE GROUPS
            //==========================================
            //
            // Explore: GET /Groups?attributes=displayName
            //
            logger.debug(`${gwName} [Explore Groups]`);
            logger.debug(`${gwName} emitting event "exploreGroups" and awaiting result`);
            this.emit('exploreGroups', req.params.baseEntity, req.query.startIndex, req.query.count, function (err, data) {
                if (err) {
                    if (!err.message) err['message'] = JSON.stringify(err);
                    logger.error(`${gwName}[${pluginName}] ${err.message}`);
                    res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                }
                else {
                    if (data) scimdata = data;
                    scimdata = addPagination(scimdata, req.query.startIndex);
                    res.send(scimdata);
                    logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                }
            });
        }
        else {
            //==========================================
            //         Get group
            //         Get group members
            //           => "user member of group" - CA IM default scim endpoint config
            //               Group having multivalue attribute members containing userName
            //==========================================
            //
            // Get group:
            // GET /Groups?filter=displayName eq "Employees"&attributes=externalId,id,members.value,displayName
            //
            // Get group members:
            // GET = /Groups?filter=members.value eq "<user-id>"&attributes=members.value,displayName&startIndex=1&count=100
            //
            var arrFilter = req.query.filter.split(" "); // members.value eq "bjensen"...
            if (arrFilter.length > 2) {
                if (arrFilter[0] === 'members.value' && arrFilter[1] === 'eq') {
                    //Get user groups
                    var userId = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, ''); // bjensen (id and not userName)
                    logger.debug(`${gwName} [Get Group Members] user id=${userId}`);
                    logger.debug(`${gwName} emitting event "getGroupMembers" and awaiting result`);
                    this.emit('getGroupMembers', req.params.baseEntity, userId, req.query.attributes, req.query.startIndex, req.query.count, function (err, data) {
                        if (err) {
                            if (!err.message) err['message'] = JSON.stringify(err);
                            logger.error(`${gwName}[${pluginName}] ${err.message}`);
                            res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                        }
                        else {
                            if (data) scimdata = data;
                            scimdata = addPagination(scimdata, req.query.startIndex);
                            res.send(scimdata);
                            logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                        }
                    });
                } // members.value (group members)
                else if (arrFilter[0] === 'displayName' && arrFilter[1] === 'eq') {
                    var groupDisplayname = req.query.filter.substring(req.query.filter.indexOf('"')).replace(/"/g, ''); // Employees (displayName and not id)
                    logger.debug(`${gwName} [Get Group] group displayName=${groupDisplayname}`);
                    logger.debug(`${gwName} emitting event "getGroup" and awaiting result`);
                    this.emit('getGroup', req.params.baseEntity, groupDisplayname, req.query.attributes, function (err, data) {
                        if (err) {
                            if (!err.message) err['message'] = JSON.stringify(err);
                            logger.error(`${gwName}[${pluginName}] ${err.message}`);
                            res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                        }
                        else {
                            if (data) scimdata.Resources.push(data);
                            scimdata = addPagination(scimdata, undefined);
                            res.send(scimdata);
                            logger.debug(`${gwName}[${pluginName}] GET = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                        }
                    });
                } // displayName (group members)

            }
        }
    }); // app.get


    //==========================================
    //           CREATE USER
    //==========================================
    //
    // POST = /Users
    // Body contains user attributes including userName (userID)
    // Body example:
    // {"active":true,"name":{"familyName":"Elshaug","givenName":"Jarle"},"schemas":["urn:scim:schemas:core:1.0"],"userName":"jael01"}
    //
    app.post('(|/:baseEntity)/Users(|.json)(|.xml)', (req, res) => {
        logger.debug(`${gwName} [Create User]`);
        var strBody = '';

        req.on('data', function (data) { //Get body
            strBody += data;
        });

        req.on('end', () => {
            var userObj = null;
            try {
                userObj = JSON.parse(strBody);
            } catch (err) { }
            if (userObj === null) {
                let err = new Error('Accepting only JSON fromatted requests');
                logger.error(`${gwName} ${err.message}`);
                res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
            }
            else {
                var userObj = JSON.parse(strBody);
                if (userObj.schemas) delete userObj['schemas'];
                logger.debug(`${gwName} POST = ${req.originalUrl} Body = ${strBody}`);
                logger.debug(`${gwName} emitting event "createUser" and awaiting result`);
                this.emit('createUser', req.params.baseEntity, userObj, function (err) {
                    if (err) {
                        if (!err.message) err['message'] = JSON.stringify(err);
                        logger.error(`${gwName} ${err.message}`);
                        res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                    }
                    else {
                        let protocol = 'http';
                        if (req.socket._tlsOptions) protocol = 'https';
                        let location = `${protocol}://${req.headers.host}${req.originalUrl}/${userObj.userName}`;
                        let scimdata =
                            {
                                "meta": {
                                    "location": location
                                },
                                "id": userObj.userName
                            }
                        res.setHeader('Location', `${location}`);
                        res.status(201).send(scimdata);
                        logger.debug(`${gwName}[${pluginName}] POST = ${req.originalUrl} Response = ${JSON.stringify(scimdata)}`);
                    }
                });
            }

        });
    }); // post


    //==========================================
    //           DELETE USER
    //==========================================
    //
    // DELETE /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
    // Note, using id (not username). Explore should therefore set id = username (userID)
    // We then have: DELETE /Users/bjensen
    //
    app.delete('(|/:baseEntity)/Users/:id', (req, res) => {
        var id = req.params.id;
        logger.debug(`${gwName} [Delete User] id=${id}`);
        logger.debug(`${gwName} emitting event "deleteUser" and awaiting result`);
        this.emit('deleteUser', req.params.baseEntity, id, function (err) {
            if (err) {
                if (!err.message) err['message'] = JSON.stringify(err);
                logger.error(`${gwName}[${pluginName}] ${err.message}`);
                res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
            }
            else {
                res.status(204).send();
                logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 204 (OK and no content)`);
            }
        });

    }); // delete



    //==========================================
    //          MODIFY USER
    //==========================================
    //
    // PATCH /Users/4aa37ddc-4985-4009-ab24-df42d37e2810
    // Note, using id (not userName). Explore should therefore set id = userName (userID)
    // We then have: PATCH /Users/bjensen
    //
    // Body contains user attributes to be updated
    // example: {"active":true,"schemas":["urn:scim:schemas:core:1.0"]}
    // example multivalue attribute: {"phoneNumbers":[{"type":"work","value":"tel:555-555-5555"},{"operation":"delete","type":"work","value":"tel:555-555-8377"}],"schemas":["urn:scim:schemas:core:1.0"]}
    //
    app.patch('(|/:baseEntity)/Users/:id', (req, res) => {
        var id = req.params.id;
        logger.debug(`${gwName} [Modify User] id=${id}`);
        var strBody = '';

        req.on('data', function (data) { // get body
            strBody += data;
        });

        req.on('end', () => {
            logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`);
            var scimdata = JSON.parse(strBody);

            // Modify multivalue element always includes a new element (no "operation" key) + original element to be deleted (operation=delete)
            // We want:
            // * All elements should have a operation key (values: delete / modify / create)
            // * "type" key should be unique, we don't allow several elements with e.g phonenumber type=work in same request
            //   (a none unique type will become overwritten if using several request for a modify user)

            delete scimdata['schemas'];
            for (let key in scimdata) {
                if (Array.isArray(scimdata[key])) {
                    var arrDel = [];
                    scimdata[key].forEach(function (element, index) {
                        if (element.operation && element.operation === 'delete') {
                            // remove this element from scimdata if similar type found
                            scimdata[key].find(function (newelement, newindex) {
                                if (element.type && newelement.type && newelement.type === element.type && (!newelement.operation || newelement.operation === 'create')) {
                                    scimdata[key][newindex].operation = 'modify'; //introducing a new operator
                                    arrDel.push(index); //index to be deleted - removing the operator.delete (or operator.create) element
                                    return true;
                                }
                                else return false;
                            });
                        }
                        else element.operation = 'create'; // introducing a new operator
                    });
                    if (arrDel.length > 0) {
                        var countDel = 0;
                        for (let i in arrDel) {
                            scimdata[key].splice(arrDel[i - countDel], 1);
                            countDel += 1;
                        }
                    }
                }
            }

            logger.debug(`${gwName} emitting event "modifyUser" and awaiting result`);
            this.emit('modifyUser', req.params.baseEntity, id, scimdata, function (err) {
                if (err) {
                    if (!err.message) err['message'] = JSON.stringify(err);
                    logger.error(`${gwName}[${pluginName}] ${err.message}`);
                    res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                }
                else {
                    let protocol = 'http';
                    if (req.socket._tlsOptions) protocol = 'https';
                    let location = `${protocol}://${req.headers.host}${req.originalUrl}`;

                    res.setHeader('Location', `${location}`);
                    res.status(200).send(scimdata);
                    logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 204 (OK and no content)`);
                }
            });

        });
    }); // patch



    //==========================================
    //          MODIFY GROUP MEMBERS
    //
    // PATCH = /Groups/<id>
    // example: PATCH = /Groups/Employees
    //
    // Body contains user attributes to be updated
    // example: {"members":[{"value":"bjensen"}],"schemas":["urn:scim:schemas:core:1.0"]}
    //==========================================
    app.patch('(|/:baseEntity)/Groups/:id', (req, res) => {
        var id = req.params.id;
        logger.debug(`${gwName} [Modify Group Members] group id=${id}`);
        var strBody = '';

        req.on('data', function (data) { // Get body
            strBody += data;
        });

        req.on('end', () => {
            logger.debug(`${gwName} PATCH = ${req.originalUrl} Body = ${strBody}`);
            var scimdata = JSON.parse(strBody);
            scimdata = scimdata.members;
            logger.debug(`${gwName} emitting event "modifyGroupMembers" and awaiting result`);
            this.emit('modifyGroupMembers', req.params.baseEntity, id, scimdata, function (err) {
                if (err) {
                    if (!err.message) err['message'] = JSON.stringify(err);
                    logger.error(`${gwName}[${pluginName}] ${err.message}`);
                    res.status(500).send(`${gwName}[${pluginName}] ${err.message}`);
                }
                else {
                    res.status(204).send();
                    logger.debug(`${gwName}[${pluginName}] PATCH = ${req.originalUrl} Response = 204 (OK and no content)`);
                }
            });
        });
    });


    //==========================================
    // Starting up...
    //==========================================

    var orgLevelConsole = logger.transports.console.level;
    var orgLevelFile = logger.transports.file.level;
    logger.transports.console.level = 'info';
    logger.transports.file.level = 'info';

    console.log();
    logger.info('===================================================================');
    if (config.localhostonly == true) {
        logger.info(`${gwName} using ${pluginName} denying other clients than localhost (127.0.0.1)`);
        if (config.certificate && config.certificate.key && config.certificate.cert) {
            // SSL
            var server = https.createServer({
                "key": fs.readFileSync(dirConfig + '/certs/' + config.certificate.key),
                "cert": fs.readFileSync(dirConfig + '/certs/' + config.certificate.cert)
            }, app).listen(config.port, 'localhost');
            logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`);
        }
        else {
            // none SSL
            var server = http.createServer(app).listen(config.port, 'localhost');
            logger.info(`${gwName} using ${pluginName} now listening on port ${config.port}...`);
        }
    } else {
        logger.info(`${gwName} using ${pluginName} accepting requests from all clients`);
        if (config.certificate && config.certificate.key && config.certificate.cert) {
            // SSL self signed cert e.g: openssl req -nodes -newkey rsa:2048 -x509 -sha256 -days 3650 -keyout key.pem -out cert.pem -subj "/O=NodeJS/OU=Testing/CN=<FQDN>"
            // Note, self signed certificate (cert.pem) also needs to be imported at the CA Connector Server
            var server = https.createServer({
                "key": fs.readFileSync(dirConfig + '/certs/' + config.certificate.key),
                "cert": fs.readFileSync(dirConfig + '/certs/' + config.certificate.cert),
                "ca": (config.certificate.ca) ? fs.readFileSync(dirConfig + '/certs/' + config.certificate.ca) : null,
            }, app).listen(config.port);
            logger.info(`${gwName} using ${pluginName} now listening on SSL/TLS port ${config.port}...`);
        }
        else {
            // none SSL
            var server = http.createServer(app).listen(config.port);
            logger.info(`${gwName} using ${pluginName} now listening on port ${config.port}...`);
        }
    }

    logger.transports.console.level = orgLevelConsole;
    logger.transports.file.level = orgLevelFile;


    // die gracefully i.e. wait for existing connections
    var gracefulShutdown = function () {
        server.close(function () {
            logger.debug(`${gwName} using ${pluginName} received kill signal - closed out remaining connections`);
            process.exit();
        });
        setTimeout(function () {
            logger.debug(`${gwName} using ${pluginName} received kill signal - Could not close connections in time, forcefully shutting down`);
            process.exit(1);
        }, 5 * 1000);
    }

    process.on('SIGTERM', gracefulShutdown); // kill
    process.on('SIGINT', gracefulShutdown);  // Ctrl+C

}; // scimgateway


// methods
ScimGateway.prototype.getPassword = function (pwEntity, configFile) {
    return utils.getPassword(pwEntity, configFile); // utils.getPassword('scimgateway.password', './config/plugin-testmode.json');
}

ScimGateway.prototype.timestamp = function () {
    return utils.timestamp();
}

ScimGateway.prototype.getArrayObject = function (Obj, element, type) {
    var found = null;
    if (Obj[element]) { // element is case sensitive
        found = Obj[element].find(function (el) {
            if (el.type && (el.type).toLowerCase() === type.toLowerCase()) return true;
            else return false;
        });
    }
    if (found) return found;
    else return {};
}

util.inherits(ScimGateway, EventEmitter);
module.exports = ScimGateway;


function addPagination(data, startIndex) {
    //If plugin not using pagination, setting totalResults = itemsPerPage
    if (!data.totalResults) data.totalResults = data.Resources.length; // Specifies the total number of results matching the Consumer query
    data.itemsPerPage = data.Resources.length;                         // Specifies the number of search results returned in a query response page
    if (startIndex) data.startIndex = startIndex;                      // The 1-based index of the first result in the current set of search results
    else data.startIndex = 1;
    if (data.startIndex > data.totalResults) { // invalid request
        data.Resources = [];
        data.itemsPerPage = 0;
    }
    return data;
}


function isValidconfig(config, arr) {
    // Check if array elements corresponds with json keys
    for (let i in arr) {
        var key = arr[i];
        var val = config[key];
        if (key === 'localhostonly') { //boolean
            if (val === undefined || typeof (val) !== 'boolean') return false;
        }
        else if (key === 'port') { // number
            if (!val || typeof (val) !== 'number') return false;
        }
        else if (!val || typeof (val) !== 'string') return false; // string
    }
    return true;
}


//
// Check and return none supported attributes
//
var notValidAttributes = function notValidAttributes(obj, validScimAttr) {
    if (validScimAttr.length < 1) return '';
    var tgt = dot.dot(obj);
    var ret = (Object.keys(tgt).filter(function (key) { //{'name.givenName': 'Jarle', emails.0.type': 'work'}
        var arrKey = key.split('.');
        if (arrKey.length === 3 && !isNaN(arrKey[1])) { //array
            if (validScimAttr.indexOf(arrKey[0]) !== -1) return false;
            else if (arrKey[2] === 'type') {
                if (validScimAttr.indexOf(arrKey[0] + '.[].type=' + tgt[key].toLowerCase()) !== -1) return false;
                else return true; //not valid
            }
            else return false; // groups and multivalue array attributes like value/primary/display/operator not needed in validScimAttr
        }
        else if (key.indexOf('meta.attributes') === 0) return false; // attributes to be cleard not needed in validScimAttr
        else return (validScimAttr.indexOf(key) === -1);
    }));
    if (ret.length > 0) return ret;
    else return null;
}
