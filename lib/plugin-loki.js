//=================================================================================
// File:    plugin-loki.js
//
// Authors: Jarle Elshaug
//          Jeffrey Gilbert (visualjeff)
//
// Purpose: SCIM endpoint locally at the ScimGateway
//          - Demonstrate userprovisioning towards a document-oriented database
//          - Using LokiJS (http://lokijs.org) for a fast, in-memory document-oriented database with persistence
//          - Two predefined test users loaded when using in-memory only (no persistence)
//          - Supporting explore, create, delete, modify and list users (including groups)
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// All attributes are supported, note multivalue "type" must be unique
//
// NOTE: Default configuration file setting {"persistence": false} gives an inMemory adapter for testing purposes
//       having two predifiend users loaded. Using {"persistence": true} gives an persistence file store located in
//       config directory with name according to configuration setting {"dbname": "loki.db"} and no no testusers loaded.
//       
//       LokiJS are well suited for handling large dataloads
//
//=================================================================================

'use strict';

const loki = require('lokijs');

// mandatory plugin initialization - start
const path = require('path');
let ScimGateway = null;
try {
    ScimGateway = require('scimgateway');
} catch (err) {
    ScimGateway = require('./scimgateway');
}
let scimgateway = new ScimGateway();
let pluginName = path.basename(__filename, '.js');
let configDir = path.join(__dirname, '..', 'config');
let configFile = path.join(`${configDir}`, `${pluginName}.json`);
let config = require(configFile).endpoint;
let validScimAttr = []; // empty array - all attrbutes are supported by endpoint
// mandatory plugin initialization - end

let endpointPasswordExample = scimgateway.getPassword('endpoint.passwordEncryptionExample.password', configFile); // demo - not in use

let dbname = (config.dbname ? config.dbname : 'loki.db');
dbname = path.join(`${configDir}`, `${dbname}`);
let db = new loki(dbname, {
    env: 'NODEJS',
    autoload: config.persistence == true ? true : false,
    autoloadCallback: loadHandler,
    autosave: config.persistence == true ? true : false,
    autosaveInterval: 10000, // 10 seconds
    adapter: (config.persistence == true) ? new loki.LokiFsAdapter() : new loki.LokiMemoryAdapter()
});

if (db.options.autoload == false) loadHandler();


function loadHandler() {

    let users = db.getCollection('users');
    if (users === null) { // if database do not exist it will be empty so intitialize here
        users = db.addCollection('users', {
            unique: ['id', 'userName']
        });
    }

    let groups = db.getCollection('groups');
    if (groups === null) {
        groups = db.addCollection('groups', {
            unique: ['displayName']
        });
    }

    if (db.options.autoload == false) { // not using persistence (physical database) => load testusers
        scimgateway.testmodeusers.forEach(function (record) {
             if (record.meta) delete record.meta;
            users.insert(record);
        });
        scimgateway.testmodegroups.forEach(function (record) {
            groups.insert(record);
        });
    }


    scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
        let action = 'exploreUsers';
        scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
        let ret = { // itemsPerPage will be set by scimgateway
            "Resources": [],
            "totalResults": null
        };

        const users = db.getCollection('users');

        if (!startIndex && !count) { // client request without paging
            startIndex = 1;
            count = users.data.length;
        }

        users.mapReduce(
            function (obj) {
                return {
                    userName: obj.userName,
                    id: obj.id,
                    externalId: obj.externalId
                }
            },
            function (array) {
                Array.prototype.push.apply(ret.Resources, array.slice(startIndex - 1, startIndex - 1 + count));
                ret.totalResults = array.length;
            }
        );
        callback(null, ret); // all explored users
    });


    scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
        scimgateway.logger.debug(pluginName + ' handling event "exploreGroups"');
        let ret = { // itemsPerPage will be set by scimgateway
            "Resources": [],
            "totalResults": null
        };

        const groups = db.getCollection('groups');

        if (!startIndex && !count) { // client request without paging
            startIndex = 1;
            count = groups.data.length;
        }

        groups.mapReduce(
            function (obj) {
                return {
                    displayName: obj.displayName,
                    id: obj.id,
                    externalId: obj.externalId
                }
            },
            function (array) {
                Array.prototype.push.apply(ret.Resources, array.slice(startIndex - 1, startIndex - 1 + count));
                ret.totalResults = array.length;
            }
        );
        callback(null, ret); // all explored groups
    });


    scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
        let action = "getUser";
        scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`);
        let retObj = {};

        const users = db.getCollection('users');
        let userObj = users.findOne({
            'userName': userName
        });

        if (!userObj) {
            let err = new Error('Could not find user with userName ' + userName);
            return callback(err);
        }
        if (!attributes) {
            userObj = stripLoki(userObj);
            return callback(null, userObj) // user with all attributes
        }
        else {
            var arrAttributes = attributes.split(',');
            for (var i = 0; i < arrAttributes.length; i++) {
                var arrSub = arrAttributes[i].split('.');
                if (arrSub.length === 2) { // eg. name.givenName
                    if (userObj[arrSub[0]]) {
                        retObj[arrSub[0]] = userObj[arrSub[0]];
                        if (userObj[arrSub[0]][arrSub[1]]) {
                            retObj[arrSub[0]][arrSub[1]] = userObj[arrSub[0]][arrSub[1]]
                        }
                    }
                } else if (arrAttributes[i] === 'password') { } // not returning password (normally not included in attributes)
                else retObj[arrAttributes[i]] = userObj[arrAttributes[i]]
            }
            retObj = stripLoki(retObj);
            callback(null, retObj);
        }
    });


    scimgateway.on('createUser', function (baseEntity, userObj, callback) {
        let action = 'createUser';
        scimgateway.logger.debug(`${pluginName} handling event "${action}" userObj=${JSON.stringify(userObj)}`);
        let notValid = scimgateway.notValidAttributes(userObj, validScimAttr); // We should check for unsupported endpoint attributes
        if (notValid) {
            let err = new Error(`unsupported scim attributes: ${notValid} ` + `(supporting only these attributes: ${validScimAttr.toString()})`);
            return callback(err);
        }

        const users = db.getCollection('users');

        if (userObj.password) delete userObj.password // exclude password db not ecrypted
        for (var key in userObj) { // convert to multivalue array
            if (!Array.isArray(userObj[key]) && scimgateway.isMultivalue('User', key)) {
                let arr = [];
                for (var el in userObj[key]) {
                    userObj[key][el].type = el;
                    arr.push(userObj[key][el]); // create
                }
                userObj[key] = arr;
            }
        }

        userObj.id = userObj.userName; //for testmode-plugin (scim endpoint) id is mandatory and set to userName
        try {
            users.insert(userObj);
        } catch (err) {
            return callback(err);
        }
        callback(null);
    });


    scimgateway.on('deleteUser', function (baseEntity, id, callback) {
        let action = 'deleteUser';
        scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id}`);

        const users = db.getCollection('users');

        let userObj = users.findOne({
            'id': id
        });
        if (typeof userObj !== undefined) {
            users.remove(userObj);
            userObj = users.findOne({
                'id': id
            });
            if (typeof userObj === undefined) {
                let err = new Error('Failed to delete user with id=' + id);
                return callback(err);
            }
            callback(null);
        }
    });


    scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
        let action = 'modifyUser';
        scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`);
        let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr); // We should check for unsupported endpoint attributes
        if (notValid) {
            let err = new Error(`unsupported scim attributes: ${notValid} `
                + `(supporting only these attributes: ${validScimAttr.toString()})`
            );
            return callback(err);
        }
        if (attrObj.password) delete attrObj.password // exclude password db not ecrypted

        const users = db.getCollection('users');
        let userObj = users.findOne({ 'id': id });

        if (typeof userObj === undefined) {
            let err = new Error(`Failed to find user with id=${id}`);
            return callback(err);
        }
        else {
            var arrUser = [];
            arrUser = userObj;
            for (var key in attrObj) {
                if (Array.isArray(attrObj[key])) { // standard, not using type (e.g groups)
                    attrObj[key].forEach(function (el) {
                        if (el.operation === 'delete') {
                            arrUser[key].find(function (e, i) {
                                if ((e.value === el.value) && el.value) { // groups
                                    arrUser[key].splice(i, 1); //delete
                                    if (arrUser[key].length < 1) delete arrUser[key];
                                    return true;
                                }
                                else return false;
                            });
                        }
                        else { // add
                            if (!arrUser[key]) arrUser[key] = [];
                            arrUser[key].push(el);
                        }
                    });
                }
                else if (scimgateway.isMultivalue('User', key)) { // customized using type instead of array (e.g mails, phones, entitlements, roles)
                    for (var el in attrObj[key]) {
                        attrObj[key][el].type = el;
                        if (attrObj[key][el].value !== '') { // create multivalue
                            if (!arrUser[key]) arrUser[key] = [];
                            var found = arrUser[key].find(function (e, i) {
                                if (e.type === el) {
                                    arrUser[key][i] = attrObj[key][el]; //modify instead of create - we want to type to be unique
                                    return true;
                                }
                                else return false;
                            });
                            if (!found) arrUser[key].push(attrObj[key][el]); // create
                        }
                        else { // delete multivalue
                            arrUser[key].find(function (e, i) {
                                if (e.type === el) {
                                    arrUser[key].splice(i, 1); //delete
                                    if (arrUser[key].length < 1) delete arrUser[key];
                                    return true;
                                }
                                else return false;
                            });
                        }
                    }
                }
                else {
                    //None multi value attribute
                    if (typeof (attrObj[key]) !== 'object') {
                        if (attrObj[key] === '') delete arrUser[key]
                        else arrUser[key] = attrObj[key];
                    }
                    else {
                        //name.formatted=Mary Lee Bianchi
                        //name.givenName=Mary
                        //name.middleName=Lee
                        //name.familyName=Bianchi
                        for (var sub in attrObj[key]) {
                            // attributes to be cleard located in meta.attributes eg: {"meta":{"attributes":["name.familyName","profileUrl","title"]}
                            if (sub === 'attributes' && Array.isArray(attrObj[key][sub])) {
                                attrObj[key][sub].forEach(function (element) {
                                    var arrSub = element.split('.');
                                    if (arrSub.length === 2) arrUser[arrSub[0]][arrSub[1]] = ''; // eg. name.familyName
                                    else arrUser[element] = '';
                                });
                            }
                            else {
                                if (attrObj[key][sub] === '') delete arrUser[key][sub]
                                else arrUser[key][sub] = attrObj[key][sub];
                            }
                        }
                    }
                }
            }
            users.update(arrUser); // persistence
            callback(null);
        }
    });


    scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
        scimgateway.logger.debug(pluginName + ' handling event "getGroup" group displayName=' + displayName + ' attributes=' + attributes);
        let retObj = {};

        const groups = db.getCollection('groups');
        let groupObj = groups.findOne({
            'displayName': displayName
        });

        if (!groupObj) {
            let err = new Error('Could not find group with displayName ' + displayName);
            return callback(err);
        } else {
            retObj.displayName = groupObj.displayName; // displayName is mandatory
            retObj.id = groupObj.id;
            retObj.externalId = groupObj.externalId;
            retObj.members = groupObj.members; // comment out this line if using "users are member of group"
        }

        callback(null, retObj)
    });


    scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
        let action = 'getGroupMembers';
        scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
        let ret = {
            "Resources": [],
            "totalResults": null
        };

        if (!startIndex && !count) { // client request without paging
            startIndex = 1;
            count = 9999999;
        }

        const groups = db.getCollection('groups');

        var i = 0;
        var j = 0;
        // find all groups user is member of
        groups.data.forEach(function (el) {
            if (el.members) {
                var userFound = el.members.find(function (element) {
                    if (element.value === id) {
                        i++;
                        return true;
                    }
                    else return false;
                });
                if (userFound && i >= startIndex && j < count) {
                    j++;
                    var userGroup = {
                        "displayName": el.displayName, // displayName is mandatory
                        "members": [{ "value": id }]    // only includes current user (not all members)
                    }
                    ret.Resources.push(userGroup);
                }
            }
        });

        ret.totalResults = i; //not needed if client or endpoint do not support paging
        callback(null, ret);
    });


    scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
        scimgateway.logger.debug(pluginName + ' handling event "getGroupUsers" groupName=' + groupName + ' attributes=' + attributes);
        let arrRet = [];

        const users = db.getCollection('users');

        users.data.forEach((user) => {
            if (user.groups) {
                user.groups.forEach((group) => {
                    if (group.value === groupName) {
                        arrRet.push({
                            'userName': user.userName
                        });
                    }
                });
            }
        });
        callback(null, arrRet);
    });


    scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
        let action = 'createGroup';
        scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`);

        const groups = db.getCollection('groups');

        groupObj.id = groupObj.displayName; //for testmode-plugin (scim endpoint) id is mandatory and set to displayName
        try {
            groups.insert(groupObj);
        } catch (err) {
            return callback(err);
        }
        callback(null);
    });


    scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
        scimgateway.logger.debug(pluginName + ' handling event "modifyGroupMembers" id=' + id + ' members=' + JSON.stringify(members));

        const groups = db.getCollection('groups');
        let groupObj = groups.findOne({ 'id': id });

        if (typeof userObj === undefined) {
            let err = new Error(`Failed to find user with id=${id}`);
            return callback(err);
        }

        if (!groupObj) {
            let err = new Error('Failed to find group with id=' + id);
            return callback(err);
        } else {
            if (Array.isArray(members)) {
                members.forEach(function (el) {
                    if (el.operation && el.operation === 'delete') {
                        // delete member from group
                        groupObj.members.find(function (element, index) {
                            if (element.value === el.value) {
                                groupObj.members.splice(index, 1);  // delete
                                if (groupObj['members'].length < 1) delete groupObj['members'];
                                return true;
                            }
                            else return false;
                        });
                    }
                    else {
                        // Add member to group
                        var newMember = {
                            "display": el.value,
                            "value": el.value
                        }
                        if (!groupObj.members) groupObj.members = [];
                        groupObj.members.push(newMember);
                    }
                });
            }
        }
        groups.update(groupObj); // persistence
        callback(null);
    });


    function stripLoki(obj) { // remove loki meta data and insert scim
        let retObj = JSON.parse(JSON.stringify(obj)); // new object - don't modify loki source
        if (retObj.meta) {
            if (retObj.meta.version) {
                retObj.meta.revision = retObj.meta.version;
                delete retObj.meta.revision;
            }
            if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString();
            if (retObj.meta.lastModified) delete retObj.meta.lastModified; // test users loaded
            if (retObj.meta.updated) {
                retObj.meta.lastModified = new Date(retObj.meta.updated).toISOString();
                delete retObj.meta.updated;
            }
            if (retObj.meta.revision) {
                retObj.meta.version = retObj.meta.revision
                delete retObj.meta.revision;
            }
        }
        if (retObj.$loki) delete retObj.$loki;
        return retObj;
    }

    process.on('SIGTERM', function () { db.close(); }); // kill
    process.on('SIGINT', function () { db.close(); });  // Ctrl+C


} // loadHandler

module.exports = scimgateway;
