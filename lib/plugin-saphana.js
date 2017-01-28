//=================================================================================
// File:    plugin-saphana.js
//
// Author:  Jarle Elshaug
//
// Purpose: SAP Hana user-provisioning for saml enabled users
//
// Prereq:  SAP Hana endpoint is up and running
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// User name    %AC%                userName    USER_NAME
// Suspended    (auto included)     active      ACTIVATE/DEACTIVATE
//
// Currently no other attributes needed for maintaining saml users
//=================================================================================

'use strict';

var ScimGateway = require('scimgateway');
var scimgateway = new ScimGateway();
var hdb = require('hdb'); // SAP Hana
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var configFile = __dirname + '/../config/' + pluginName + '.json';
var config = require(configFile).endpoint;
var endpointHost = config.host;
var endpointPort = config.port;
var endpointUsername = config.username;
var endpointPassword = scimgateway.getPassword('endpoint.password', configFile);
var endpointSamlProvider = config.saml_provider;
var hdbClient = hdb.createClient({
    host: endpointHost,
    port: endpointPort,
    user: endpointUsername,
    password: endpointPassword
});

var validScimAttr = [   // array containing scim attributes supported by our plugin code
    "userName",         // userName is mandatory
    "active"            // active is mandatory
];


//==========================================
//             EXPLORE USERS
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// startIndex = Pagination - The 1-based index of the first result in the current set of search results
// count      = Pagination - Number of elements to be returned in the current set of search results
// callback   = Resources array to be filled with objects containing userName and id
//              (userName and id set to the same value)
//              e.g [{"userName":"bjensen","id":"bjensen"},{"userName":"jsmith","id":"jsmith"}]
//
// If endpoint supports paging: totalResults should be set to the total numbers of elements (users) at endpoint.
// 
// => SAP Hana pagination not implemented
//==========================================
scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
    var action = 'exploreUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    var ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    hdbClient.connect(function (err) {
        if (err) {
            var err = new Error('Explore-Users hdbcClient.connect: SAP Hana client connect error: ' + err.message);
            return callback(err);
        }
        // Find all SAML_ENABLED users
        var sqlQuery = "select USER_NAME from SYS.USERS where IS_SAML_ENABLED like 'TRUE'";
        hdbClient.exec(sqlQuery, function (err, rows) {
            hdbClient.end();
            if (err) {
                var err = new Error('Explore-Users hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                return callback(err);
            }
            for (var row in rows) {
                var scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
                    "userName": rows[row].USER_NAME,
                    "id": rows[row].USER_NAME
                };
                ret.Resources.push(scimUser);
            }
            callback(null, ret); // all explored users
        }); // exec
    }); // connect
});


//==========================================
//             EXPLORE GROUPS
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// startIndex = Pagination - The 1-based index of the first result in the current set of search results
// count      = Pagination - Number of elements to be returned in the current set of search results
// callback = Resources array to be filled with objects containing group displayName and id
//            (displayName and id set to the same value)
//            e.g [{"displayName":"Admins","id":"Admins"},{"displayName":"Employees","id":"Employees"}]
//            If endpoint paging support: totalResults, itempsPerPage and startIndex should also be set
//
// If endpoint supports paging: totalResults should be set to the total numbers of elements (groups) at endpoint.
//
// If we do not support groups, callback(null, null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
    var action = 'exploreGroups';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    callback(null, null); // groups not implemented
});


//==========================================
//             GET USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// userName   = user id (eg. bjensen)
// attributes = scim attributes to be returned in callback
// callback = user object containing the scim userattributes/values
//      eg: {"id":"bjensen","name":{"formatted":"Ms. Barbara J Jensen III","familyName":"Jensen","givenName":"Barbara"}}
//
// Note, CA Provisioning use two types of "Get User"
// 1. Check if user exist - attributes=userName and/or id
// 2. Retrive user - attributes=<list of all attributes>
//==========================================
scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
    var action = "getUser";
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`);

    hdbClient.connect(function (err) {
        if (err) {
            var err = new Error('Get-User hdbcClient.connect: SAP Hana client connect error: ' + err.message);
            return callback(err);
        }
        var arrAttr = attributes.split(',');
        if (arrAttr.length == 2) { // userName and id - user lookup
            var sqlQuery = "select USER_NAME from SYS.USERS where USER_NAME like '" + userName + "'";
            hdbClient.exec(sqlQuery, function (err, rows) {
                hdbClient.end();
                if (err) {
                    var err = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                    return callback(err);
                }
                if (rows.length == 1) {
                    var userObj = { //userName and id is mandatory
                        "userName": rows[0].USER_NAME,
                        "id": rows[0].USER_NAME,
                    };
                    callback(null, userObj);
                } else {
                    var err = new Error('Get-User hdbcClient.exec: User not found sqlQuery = ' + sqlQuery);
                    return callback(err);
                }
            }); //exec
        }
        else { // all endpoint supported attributes (includes active)
            var sqlQuery = "select USER_NAME, USER_DEACTIVATED from SYS.USERS where USER_NAME like '" + userName + "'";
            hdbClient.exec(sqlQuery, function (err, rows) {
                hdbClient.end();
                if (err) {
                    var err = new Error('Get-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                    return callback(err);
                }
                if (rows.length == 1) {
                    var userObj = { //userName and id is mandatory
                        "userName": rows[0].USER_NAME,
                        "id": rows[0].USER_NAME,
                        "active": !JSON.parse((rows[0].USER_DEACTIVATED).toLowerCase())
                    };
                    callback(null, userObj);
                } else {
                    var err = new Error('Get-User hdbcClient.exec: User not found sqlQuery = ' + sqlQuery);
                    return callback(err);
                }
            }); //exec
        }
    }); //connect  
});


//==========================================
//           CREATE USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// userObj    = user object containing userattributes according to scim standard
// callback   = null (OK) or error object
//==========================================
scimgateway.on('createUser', function (baseEntity, userObj, callback) {
    var action = 'createUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userObj=${JSON.stringify(userObj)}`);

    var notValid = scimgateway.notValidAttributes(userObj, validScimAttr);
    if (notValid) {
        var err = new Error('unsupported scim attributes: ' + notValid
            + ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
        );
        return callback(err);
    }

    hdbClient.connect(function (err) {
        if (err) {
            var err = new Error('Create-User hdbcClient.connect: SAP Hana client connect error: ' + err.message);
            return callback(err);
        }
        // SAPHana create user do not need any additional provisioning attributes to be included				  
        // var sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ANY FOR SAML PROVIDER ' + endpointSamlProvider;
        // var sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider;
        var sqlQuery = 'CREATE USER ' + userObj.userName + ' WITH IDENTITY ' + "'" + userObj.userName + "'" + ' FOR SAML PROVIDER ' + endpointSamlProvider + ' SET PARAMETER CLIENT = ' + "'103'";
        hdbClient.exec(sqlQuery, function (err, rows) {
            hdbClient.end();
            if (err) {
                var err = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                return callback(err);
            }
            sqlQuery = 'GRANT NG_REPORTING_ROLE TO ' + userObj.userName;
            hdbClient.exec(sqlQuery, function (err, rows) {
                hdbClient.end();
                if (err) {
                    var err = new Error('Create-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                    return callback(err);
                }
                callback(null); // user now created
            }); // exec                        
        }); // exec
    }); // connect
});


//==========================================
//           DELETE USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// id         = user id
// callback   = null (OK) or error object
// Note, if groups are supported, provisioning will also do getGroupMembers (if using default "users member of group)
//       and then remove user from groups before deleting user
//==========================================
scimgateway.on('deleteUser', function (baseEntity, id, callback) {
    var action = 'deleteUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id}`);
    hdbClient.connect(function (err) {
        if (err) {
            var err = new Error('Delete-User hdbcClient.connect: SAP Hana client connect error: ' + err.message);
            return callback(err);
        }
        var sqlQuery = 'DROP USER ' + id;
        hdbClient.exec(sqlQuery, function (err, rows) {
            hdbClient.end();
            if (err) {
                var err = new Error('Delete-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                return callback(err);
            }
            callback(null); // successfully deleted
        }); // exec
    }); // connect
});


//==========================================
//          MODIFY USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// id         = user id
// attrObj    = object containing userattributes according to scim standard (but multi-value attributes includes additional operation value create/delete/modify)
// callback   = null (OK) or error object
//==========================================
scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
    var action = 'modifyUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`);

    var notValid = scimgateway.notValidAttributes(attrObj, validScimAttr);
    if (notValid) {
        var err = new Error('unsupported scim attributes: ' + notValid
            + ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
        );
        return callback(err);
    }

    var sqlAction = '';
    if (attrObj.active != undefined) {
        if (sqlAction.length === 0) sqlAction = (attrObj.active === true) ? 'ACTIVATE' : 'DEACTIVATE';
        else sqlAction += (attrObj.active === true) ? ' ACTIVATE' : ' DEACTIVATE';
    } //Add more attribute checks here according supported endpoint attributes

    hdbClient.connect(function (err) {
        if (err) {
            var err = new Error('Modify-User hdbcClient.connect: SAP Hana client connect error: ' + err.message);
            return callback(err);
        }
        var sqlQuery = 'ALTER USER ' + id + ' ' + sqlAction;
        hdbClient.exec(sqlQuery, function (err, rows) {
            hdbClient.end();
            if (err) {
                var err = new Error('Modify-User hdbcClient.exec: SAP Hana client execute error: ' + err.message + ' sqlQuery = ' + sqlQuery);
                return callback(err);
            }
            callback(null); // user successfully updated
        }); //execute
    }); //connect
});


//==========================================
//             GET GROUP
//
// baseEntity  = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// displayName = group name
// attributes  = scim attributes to be returned in callback (displayName and members is mandatory)
// callback    = object containing group displayName and id (+ members if using default "users are member of group")
//
// eg. using default "users are member of group":
//     {"displayName":"Admins","id":"Admins","members":[{"value":"bjensen","display":"bjensen"]}
//
// eg. using "groups are member of user":
//     {"displayName":"Admins","id":"Admins"}
//
// If we do not support groups, callback(null, null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
    var action = 'getGroup'
    scimgateway.logger.debug(`${pluginName} handling event "getGroup" group displayName=${displayName} attributes=${attributes}`);
    callback(null, null); // groups not implemented
});


//==========================================
//             GET GROUP MEMBERS
//
// retrieve all users for a spesific group WHEN:
// "user member of group" - CA IM default scim endpoint config
// Group having multivalue attribute members containing userName
// 
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// id         = user id (eg. bjensen)
// attributes = attributes to be returned in callback (we only return the name of groups - displayName and current user as member)
// callback   = array of objects containing groups with current user as member to be returned 
//      e.g [{"displayName":"Admins","members": [{ "value": bjensen}]}, {"displayName":"Employees", "members": [{ "value": bjensen}]}]
//
// If endpoint supports paging: totalResults shold be set to the total numbers of elements (group members) at endpoint.
//
// If we do not support groups (or "user member of group"), callback(null, []) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
    var action = 'getGroupMembers'
    scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
    var ret = {
        "Resources": [],
        "totalResults": null
    };
    callback(null, ret);  // groups not implemented
});


//==========================================
//             GET GROUP USERS
//
// retrieve all users for a spesific group WHEN:
// "group member of user" - User having multivalue attribute groups containing value=GroupName
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// groupName  = group name (eg. UserGroup-1)
// attributes = scim attributes to be returned in callback
// callback   = array containing the userName's'
//      eg: [{"userName", "bjensen"}, {"userName", "jsmith"}]
//
// If we do not support groups (or "group member of user"), callback(null, []) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    var action = 'getGroupUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupName=${groupName} attributes=${attributes}`);
    var arrRet = [];
    callback(null, arrRet);
});


//==========================================
//          MODIFY GROUP MEMBERS
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// id         = group name (eg. Admins)
// members    = array of objects containing groupmembers eg: {"value":"bjensen"}, {"operation":"delete","value":"jsmith"}
// callback   = null (OK) or error object
// 
// If we do not support groups, callback(null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
    var action = 'modifyGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`);
    callback(null);
});
