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

var hdb = require('hdb'); // SAP Hana
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var ScimGateway = require('./scimgateway');
var scimgateway = new ScimGateway(pluginName);
var pwCrypt = require("../lib/utils");
var configFile = __dirname + '/../config/' + pluginName + '.json';
var config = require(configFile).endpoint;
var endpointHost = config.host;
var endpointPort = config.port;
var endpointUsername = config.username;
var endpointPassword = pwCrypt.getPassword('endpoint.password', configFile);
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
// startIndex = Pagination - The 1-based index of the first result in the current set of search results
// count      = Pagination - Number of elements to be returned in the current set of search results
// callback   = Resources array to be filled with objects containing userName and id
//              (userName and id set to the same value)
//              e.g [{"userName":"bjensen","id":"bjensen"},{"userName":"jsmith","id":"jsmith"}]
//
// If endpoint paging support: totalResults and startIndex should also be set.
// totalResults is the total numbers of elements (users) at endpoint.
// 
// => SAP Hana pagination not implemented
//==========================================
scimgateway.on('explore-users', function (startIndex, count, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "explore-user"');
    var ret = { // itemsPerPage will be set by scimgateway
        "totalResults": null,
        "startIndex": null,
        "Resources": []
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
// startIndex = Pagination - The 1-based index of the first result in the current set of search results
// count      = Pagination - Number of elements to be returned in the current set of search results
// callback = Resources array to be filled with objects containing group displayName and id
//            (displayName and id set to the same value)
//            e.g [{"displayName":"Admins","id":"Admins"},{"displayName":"Employees","id":"Employees"}]
//            If endpoint paging support: totalResults, itempsPerPage and startIndex should also be set
//
// If endpoint paging support: totalResults and startIndex should also be set.
// totalResults is the total numbers of elements (groups) at endpoint.
//
// If we do not support groups, callback(null, null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('explore-groups', function (startIndex, count, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "explore-groups"');
    callback(null, null); // groups not implemented
});


//==========================================
//             GET USER
//
//==========================================
scimgateway.on('get-user', function (userName, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-user" userName=' + userName + ' attributes=' + attributes);

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
// userObj = user object containing userattributes according to scim standard
// callback = null (OK) or error object
//==========================================
scimgateway.on('create-user', function (userObj, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "create-user" userObj=' + JSON.stringify(userObj));

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
// id       = user id
// callback = null (OK) or error object
// Note, if groups are supported, provisioning will also do get-group-members and remove user from groups before deleting user
//==========================================
scimgateway.on('delete-user', function (id, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "delete-user" id=' + id);
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
// id       = user id
// attrObj  = object containing userattributes according to scim standard (but multi-value attributes includes additional operation value create/delete/modify)
// callback = null (OK) or error object
//==========================================
scimgateway.on('modify-user', function (id, attrObj, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "modify-user" id=' + id + ' attrObj=' + JSON.stringify(attrObj));

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
// displayName   = group name
// attributes = scim attributes to be returned in callback (displayName and members is mandatory)
// callback = object containing the scim group information including members
//      eg: {"displayName":"Admins","id":"Admins","members":[{"value":"bjensen","display":"bjensen"}
//
// // If we do not support groups, callback(null, null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('get-group', function (displayName, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-group" group displayName=' + displayName + ' attributes=' + attributes);
    callback(null, null); // groups not implemented
});


//==========================================
//             GET GROUP MEMBERS
//
// id         = user id (eg. bjensen)
// attributes = attributes to be returned in callback (we only return the name of groups - displayName and current user as member)
// callback   = array of objects containing groups with current user as member to be returned 
//      e.g [{"displayName":"Admins","members": [{ "value": bjensen}]}, {"displayName":"Employees", "members": [{ "value": bjensen}]}]
//
// If we do not support groups, callback(null, []) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('get-group-members', function (id, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-group-members" user id=' + id + ' attributes=' + attributes);
    var arrRet = [];
    callback(null, arrRet);  // groups not implemented
});


//==========================================
//          MODIFY GROUP MEMBERS
//
// id       = group name (eg. Admins)
// members = array of objects containing groupmembers eg: {"value":"bjensen"}, {"operation":"delete","value":"jsmith"}
// callback = null (OK) or error object
// 
// If we do not support groups, callback(null) with no additional code lines
//
// => SAP Hana groups not implemented
//==========================================
scimgateway.on('modify-group-members', function (id, members, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "modify-group-members" id=' + id + ' members=' + JSON.stringify(members));
    callback(null);
});
