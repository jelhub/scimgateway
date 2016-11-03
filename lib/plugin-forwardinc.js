//=================================================================================
// File:    plugin-forwardinc.js
//
// Author:  Jarle Elshaug
//
// Purpose: SOAP Webservice user-provisioning for endpoint "Forwardinc"
//
// Prereq:  Forwardinc webservice is up and running
//          Forwardinc comes with CA IM SDK (SDKWS)
//          For details please see:
//          https://docops.ca.com/ca-identity-manager/12-6-8/EN/programming/connector-programming-reference/sdk-sample-connectors/sdkws-sdk-web-services-connector/sdkws-sample-connector-build-requirements
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                            Endpoint
// -----------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        userID
// Password     %P%                                     password                        password
// First Name   %UF%                                    name.givenName                  firstName
// Last Name    %UL%                                    name.familyName                 lastName
// Full Name    %UN%                                    name.formatted                  displayName
// Job title    %UT%                                    title                           title
// Email        %UE% (Emails, type=Work)                emails.[].type=work             emailAddress
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.[].type=work       phoneNumber
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.[].type=company    company
//
//=================================================================================

'use strict';

var soap = require('soap');
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var ScimGateway = require('./scimgateway');
var scimgateway = new ScimGateway(pluginName);
var pwCrypt = require("../lib/utils");
var configFile = __dirname + '/../config/' + pluginName + '.json';
var config = require(configFile).endpoint;
var endpointUrlUser = config.wsdl_userservice + '?wsdl';
var endpointUrlGroup = config.wsdl_groupservice + '?wsdl';
var endpointUsername = config.username;
var endpointPassword = pwCrypt.getPassword('endpoint.password', configFile);

var _client = {};

var validScimAttr = [   // array containing scim attributes supported by our plugin code
    "userName",         // userName is mandatory
    "active",           // active is mandatory
    "password",
    "name.givenName",
    "name.familyName",
    "name.formatted",
    "title",
    //"emails",             // accepts all multivalues for this key
    "emails.[].type=work",  // accepts multivalues if type value equal work (lowercase) 
    //"phoneNumbers",
    "phoneNumbers.[].type=work",
    //"entitlements"
    "entitlements.[].type=company"
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
// => forwardinc pagination not implemented
//==========================================
scimgateway.on('explore-users', function (startIndex, count, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "explore-user"');
    var ret = { // itemsPerPage will be set by scimgateway
        "totalResults": null,
        "startIndex": null,
        "Resources": []
    };

    getClient('user', function (err, client) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Users" };
        client.searchUsers(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result.return) {
                var err = new Error('Explore-Users searchUsers: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }

            var hdl = result.return.handleId;

            if (result.return.size < 1) {
                soapRequest = { handleId: hdl };
                client.releaseHandle(soapRequest, function (err, result, body) { });                
                return callback(null, ret) // no users found
            }

            soapRequest = {
                handleId: hdl,
                startIndex: 0,
                endIndex: result.return.size - 1
            };
            client.searchPagedUser(soapRequest, function (err, result, body) {
                if (err) return callback(err);
                else if (!result.return) {
                    var err = new Error('Explore-Users searchPagedUsers: Got empty response on soap request: ' + soapRequest);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(pluginName + ' searchPagedUser soap result: ' + JSON.stringify(result));
                result.return.forEach(function (element) {
                    var scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
                        "userName": element.userID,
                        "id": element.userID
                    };
                    ret.Resources.push(scimUser);
                });
                soapRequest = { handleId: hdl };
                client.releaseHandle(soapRequest, function (err, result, body) { });

                callback(null, ret); // all explored users

            }); // searchPagedUser
        }); // searchUsers
    }); // getClient
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
//==========================================
scimgateway.on('explore-groups', function (startIndex, count, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "explore-groups"');
    var ret = { // itemsPerPage will be set by scimgateway
        "totalResults": null,
        "startIndex": null,
        "Resources": []
    };

    getClient('group', function (err, client) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Groups" };
        client.searchGroup(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result) return callback(null, ret); // no groups
            else if (!result.return) {
                var err = new Error('Explore-Groups searchGroup: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(pluginName + ' searchGroup soap result: ' + JSON.stringify(result));
            result.return.forEach(function (element) {
                var scimGroup = { //displayName and id is mandatory, note: we set id=displayName
                    "displayName": element.groupID,
                    "id": element.groupID
                };
                ret.Resources.push(scimGroup);
            });

            callback(null, ret); // all explored groups

        }); // searchGroup
    }); // getClient
});


//==========================================
//             GET USER
//
//==========================================
scimgateway.on('get-user', function (userName, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-user" userName=' + userName + ' attributes=' + attributes);
    getClient('user', function (err, client) {
        if (err) return callback(err);
        var arrAttr = attributes.split(',');
        if (arrAttr.length == 2) { // userName and id
            var soapRequest = { "name": userName };
            client.pingUser(soapRequest, function (err, result, body) {
                if (err) return callback(err);
                else if (!result.return) {
                    var err = new Error('Get-User pingUser : Got empty response on soap request: ' + soapRequest);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(pluginName + ' pingUser soap result: ' + JSON.stringify(result));
                var userObj = {
                    "userName": userName,
                    "id": userName,
                }
                callback(null, userObj);
            });
        }
        else { // all endpoint supported attributes
            var soapRequest = { "userID": userName };
            client.lookupUser(soapRequest, function (err, result, body) {
                if (err) return callback(err);
                else if (!result.return) {
                    var err = new Error('Get-User lookupUser: Got empty response on soap request: ' + soapRequest);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(pluginName + ' lookupUser soap result: ' + JSON.stringify(result));
                var userObj = {
                    "userName": userName,
                    "id": userName,
                    "password": result.return.password,
                    "name": {
                        "givenName": result.return.firstName,
                        "familyName": result.return.lastName,
                        "formatted": result.return.displayName
                    },
                    "title": result.return.title,
                    "emails": [{
                        "value": result.return.emailAddress,
                        "type": "work"
                    }],
                    "phoneNumbers": [{
                        "value": result.return.phoneNumber,
                        "type": "work"
                    }],
                    "entitlements": [{
                        "value": result.return.company,
                        "type": "Company"
                    }]
                }
                callback(null, userObj);
            });
        } // else
    }); // getClient
});


//==========================================
//           CREATE USER
//
// userObj = user object containing userattributes according to scim standard
// callback = null (OK) or error object
//==========================================
scimgateway.on('create-user', function (userObj, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "create-user" userObj=' + JSON.stringify(userObj));
    getClient('user', function (err, client) {
        if (err) return callback(err);
        var notValid = scimgateway.notValidAttributes(userObj, validScimAttr);
        if (notValid) {
            var err = new Error('unsupported scim attributes: ' + notValid
                + ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
            );
            return callback(err);
        }

        if (!userObj.name) userObj.name = {};
        if (!userObj.emails) userObj.emails = [{}];
        if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}];
        if (!userObj.entitlements) userObj.entitlements = [{}];

        var soapRequest = {
            "user": {
                "userID": userObj.userName,
                "password": userObj.password || null,
                "firstName": userObj.name.givenName || null,
                "lastName": userObj.name.familyName || null,
                "displayName": userObj.name.formatted || null,
                "title": userObj.title || null,
                "emailAddress": userObj.emails[0].value || null,
                "phoneNumber": userObj.phoneNumbers[0].value || null,
                "company": userObj.entitlements[0].value || null
            }
        };

        client.addUser(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result.return) {
                var err = new Error('Create-User addUser: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }
            callback(null);
        });
    });
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
    getClient('user', function (err, client) {
        if (err) return callback(err);
        var soapRequest = { "userID": id };
        client.removeUser(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result.return) {
                var err = new Error('Delete-User removeUser: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }
            callback(null);
        });
    });
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

    // forwardinc modify user will blank all attributes not included in soap request...
    // We therefore need to to retrieve all user attributes from forwardinc and merge with updated attributes. 
    // Modify user will then include all user attributes.

    this.emit('get-user', id, "userName,id,and,all,the,rest", function (err, userObj) {
        if (err) {
            return callback(err);
        }
        else {
            getClient('user', function (err, client) {
                if (err) return callback(err);
                var notValid = scimgateway.notValidAttributes(attrObj, validScimAttr);
                if (notValid) {
                    var err = new Error('unsupported scim attributes: ' + notValid
                        + ' (supporting only these attributes: ' + validScimAttr.toString() + ')'
                    );
                    return callback(err);
                }

                if (!attrObj.name) attrObj.name = {};
                if (!attrObj.emails) attrObj.emails = [{}];
                if (!attrObj.phoneNumbers) attrObj.phoneNumbers = [{}];
                if (!attrObj.entitlements) attrObj.entitlements = [{}];

                var clearedObj = {}; // include cleared attributes, attrObj exampel: { meta: { attributes: [ 'name.givenName', 'title' ] } }
                clearedObj.name = {};
                if (attrObj.meta && attrObj.meta.attributes && Array.isArray(attrObj.meta.attributes)) {
                    attrObj.meta.attributes.forEach(function (element) {
                        var arrSub = element.split('.');
                        if (arrSub.length === 2) clearedObj[arrSub[0]][arrSub[1]] = ''; // eg. name.givenName
                        else clearedObj[element] = '';
                    });
                }

                var soapRequest = {
                    "user": {
                        "userID": id,
                        "password": (clearedObj.password === '') ? '' : attrObj.password || userObj.password,
                        "firstName": (clearedObj.name.givenName === '') ? '' : attrObj.name.givenName || userObj.name.givenName,
                        "lastName": (clearedObj.name.familyName === '') ? '' : attrObj.name.familyName || userObj.name.familyName,
                        "displayName": (clearedObj.name.formatted === '') ? '' : attrObj.name.formatted || userObj.name.formatted,
                        "emailAddress": (attrObj.emails[0].operation && attrObj.emails[0].operation === 'delete') ? null : attrObj.emails[0].value || userObj.emails[0].value,
                        "phoneNumber": (attrObj.phoneNumbers[0].operation && attrObj.phoneNumbers[0].operation === 'delete') ? null : attrObj.phoneNumbers[0].value || userObj.phoneNumbers[0].value,
                        "company": (attrObj.entitlements[0].operation && attrObj.entitlements[0].operation === 'delete') ? null : attrObj.entitlements[0].value || userObj.entitlements[0].value,
                        "title": (clearedObj.title === '') ? '' : attrObj.title || userObj.title
                    }
                };

                client.modifyUser(soapRequest, function (err, result, body) {
                    if (err) return callback(err);
                    else if (!result.return) {
                        var err = new Error('Modify-User modifyUser: Got empty response on soap request: ' + soapRequest);
                        err.name = 'NoResult';
                        return callback(err);
                    }
                    callback(null);
                });
            });
        }
    });
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
//==========================================
scimgateway.on('get-group', function (displayName, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-group" group displayName=' + displayName + ' attributes=' + attributes);
    getClient('group', function (err, client) {
        if (err) return callback(err);
        var soapRequest = { "groupID": displayName };
        client.lookupGroup(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result.return) {
                var err = new Error('Get-Group lookupGroup: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(pluginName + ' lookupGroup soap result: ' + JSON.stringify(result));
            var retObj = {};
            retObj.displayName = result.return.groupID; // displayName is mandatory
            retObj.id = result.return.groupID;
            if (Array.isArray(result.return.members)) {
                retObj.members = [];
                result.return['members'].forEach(function (element) {
                    retObj.members.push({ "value": element });
                });
            }
            callback(null, retObj);
        });
    });
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
//==========================================
scimgateway.on('get-group-members', function (id, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "get-group-members" user id=' + id + ' attributes=' + attributes);
    var arrRet = [];
    getClient('group', function (err, client) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Groups" };
        client.searchGroup(soapRequest, function (err, result, body) {
            if (err) return callback(err);
            else if (!result) return callback(null, arrRet); // no groups
            else if (!result.return) {
                var err = new Error('Get-Group-Members searchGroup: Got empty response on soap request: ' + soapRequest);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(pluginName + ' searchGroup soap result: ' + JSON.stringify(result));
            result.return.forEach(function (element) {
                if (Array.isArray(element.members)) {
                    element.members.forEach(function (el) {
                        if (el === id) { //user is member of group
                            var userGroup = {
                                "displayName": element.groupID, // displayName is mandatory
                                "members": [{ "value": el }]    // only includes current user (not all members)
                            }
                            arrRet.push(userGroup);
                        }
                    });
                }
            });
            callback(null, arrRet);
        });
    });
});


//==========================================
//          MODIFY GROUP MEMBERS
//
// id       = group name (eg. Admins)
// members = array of objects containing groupmembers eg: {"value":"bjensen"}, {"operation":"delete","value":"jsmith"}
// callback = null (OK) or error object
// 
// If we do not support groups, callback(null) with no additional code lines
//==========================================
scimgateway.on('modify-group-members', function (id, members, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "modify-group-members" id=' + id + ' members=' + JSON.stringify(members));
    if (Array.isArray(members)) {
        getClient('group', function (err, client) {
            if (err) return callback(err);
            members.forEach(function (el) {
                if (el.operation && el.operation === 'delete') {
                    // delete member from group
                    var soapRequest = {
                        "groupID": id,
                        "userID": el.value
                    };
                    client.removeUserFromGroup(soapRequest, function (err, result, body) {
                        if (err) return callback(err);
                        else if (!result.return) {
                            var err = new Error('Modify-Group-Members removeUserFromGroup: Got empty response on soap request: ' + soapRequest);
                            err.name = 'NoResult';
                            return callback(err);
                        }
                        callback(null);
                    });
                }
                else {
                    var soapRequest = { // add member to group
                        "groupID": id,
                        "userID": el.value
                    };
                    client.assignUserToGroup(soapRequest, function (err, result, body) {
                        if (err) return callback(err);
                        else if (!result.return) {
                            var err = new Error('Modify-Group-Members assignUserToGroup: Got empty response on soap request: ' + soapRequest);
                            err.name = 'NoResult';
                            return callback(err);
                        }
                        callback(null);
                    });
                }
            });
        });
    } // if Array
    else callback(null);
});



var getClient = function (type, callback) {
    if (_client[type]) { // client already exist
        callback(null, _client[type]);
        return;
    }
    if (type === 'user') var url = endpointUrlUser;
    else var url = endpointUrlGroup;
    var wsdlOptions = {};
    soap.createClient(url, wsdlOptions, function (err, client) {
        if (err) return callback(err);
        client.setSecurity(new soap.WSSecurity(endpointUsername, endpointPassword, { passwordType: "PasswordText", hasTimeStamp: false }))
        _client[type] = client; // client created
        callback(null, _client[type]);
    });
}
