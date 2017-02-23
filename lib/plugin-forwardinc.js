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

var ScimGateway = require('scimgateway');
var scimgateway = new ScimGateway();
var soap = require('soap');
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var configDir = __dirname + '/../config';
var configFile = configDir + '/' + pluginName + '.json';
var config = require(configFile).endpoint;
var wsdlDir = configDir + '/wsdls';

var endpointUsername = config.username;
var endpointPassword = scimgateway.getPassword('endpoint.password', configFile);

var _serviceClient = {};

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


///==========================================
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
// => forwardinc pagination not implemented
//==========================================
scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
    var action = 'exploreUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    var ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Users" };
        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.searchUsers()
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
            if (err) return callback(err);
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }

            var hdl = result.return.handleId;

            if (result.return.size < 1) {
                soapRequest = { "handleId": hdl };
                serviceClient.releaseHandle(soapRequest, function (err, result, body) { });
                return callback(null, ret) // no users found
            }

            soapRequest = {
                "handleId": hdl,
                "startIndex": 0,
                "endIndex": result.return.size - 1
            };
            serviceClient.searchPagedUser(soapRequest, function (err, result, body) {
                if (err) return callback(err);
                else if (!result.return) {
                    var err = new Error(`exploreUsers searchPagedUsers: Got empty response on soap request: ${soapRequest}`);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);

                result.return.forEach(function (element) {
                    var scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
                        "userName": element.userID,
                        "id": element.userID
                    };
                    ret.Resources.push(scimUser);
                });
                soapRequest = { handleId: hdl };
                serviceClient.releaseHandle(soapRequest, function (err, result, body) { });

                callback(null, ret); // all explored users

            }); // searchPagedUser
        }); // searchUsers
    }); // getClient
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
//==========================================
scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
    var action = 'exploreGroups';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    var ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Groups" };
        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.searchGroup()
            scimgateway.logger.debug(`${pluginName} ${action} ${config.exploreGroups.method} request: ${serviceClient.lastRequest}`);
            if (err) return callback(err);
            else if (!result) return callback(null, ret); // no groups
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
            result.return.forEach(function (element) {
                var scimGroup = { //displayName and id is mandatory, note: we set id=displayName
                    "displayName": element.groupID,
                    "id": element.groupID
                };
                ret.Resources.push(scimGroup);
            });

            callback(null, ret); // all explored groups

        }); // searchGroup
    }); // getServiceClient
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
    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var arrAttr = attributes.split(',');
        if (arrAttr.length < 3) { // userName and/or id - check if user exist
            var soapRequest = { "userID": userName };
            // Could use pingUser, but instead using method lookupUser that is assigned to getUser in the configuration file 
            // var soapRequest = { "name": userName };
            // serviceClient.pingUser()
            serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.lookupUser()
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
                if (err) return callback(err);
                else if (!result.return) {
                    scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                    var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
                var userObj = {
                    "userName": userName,
                    "id": userName,
                }
                callback(null, userObj);
            });
        }
        else { // all endpoint supported attributes
            var soapRequest = { "userID": userName };
            serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.lookupUser()
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
                if (err) return callback(err);
                else if (!result.return) {
                    scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                    var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                    err.name = 'NoResult';
                    return callback(err);
                }
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
                var userObj = {
                    "userName": userName, // not needed
                    "id": userName,       // not needed
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
    }); // getServiceClient
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

    getServiceClient(baseEntity, action, function (err, serviceClient) {

        if (err) return callback(err);
        var notValid = scimgateway.notValidAttributes(userObj, validScimAttr);
        if (notValid) {
            var err = new Error(`unsupported scim attributes: ${notValid} `
                + `(supporting only these attributes: ${validScimAttr.toString()})`
            );
            return callback(err);
        }

        if (!userObj.name) userObj.name = {};
        if (!userObj.emails) userObj.emails = [{}];
        if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}];
        if (!userObj.entitlements) userObj.entitlements = [{}];

        let objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work') || {};
        let objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work') || {};
        let objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company') || {};

        var soapRequest = {
            "user": {
                "userID": userObj.userName,
                "password": userObj.password || null,
                "firstName": userObj.name.givenName || null,
                "lastName": userObj.name.familyName || null,
                "displayName": userObj.name.formatted || null,
                "title": userObj.title || null,
                "emailAddress": objWorkEmail.value || null,
                "phoneNumber": objWorkPhone.value || null,
                "company": objCompanyEntitlement.value || null
            }
        };

        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.addUser()
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
            if (err) return callback(err);
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
            callback(null);
        });
    });
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
    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var soapRequest = { "userID": id };
        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.removeUser()
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
            if (err) return callback(err);
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
            callback(null);
        });
    });
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

    // forwardinc modify user will blank all attributes not included in soap request...
    // We therefore need to to retrieve all user attributes from forwardinc and merge with updated attributes. 
    // Modify user will then include all user attributes.

    this.emit('getUser', baseEntity, id, "userName,id,and,all,the,rest", function (err, userObj) {
        if (err) {
            return callback(err);
        }
        else {
            getServiceClient(baseEntity, action, function (err, serviceClient) {
                if (err) return callback(err);
                var notValid = scimgateway.notValidAttributes(attrObj, validScimAttr);
                if (notValid) {
                    var err = new Error(`unsupported scim attributes: ${notValid} `
                        + `(supporting only these attributes: ${validScimAttr.toString()})`
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

                let attrObjWorkEmail = scimgateway.getArrayObject(attrObj, 'emails', 'work') || {};
                let objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work') || {};
                let attrObjWorkPhone = scimgateway.getArrayObject(attrObj, 'phoneNumbers', 'work') || {};
                let objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work') || {};
                let attrObjCompanyEntitlement = scimgateway.getArrayObject(attrObj, 'entitlements', 'company') || {};
                let objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company') || {};

                let email = (attrObjWorkEmail.operation && attrObjWorkEmail.operation === 'delete') ? '' : attrObjWorkEmail.value;
                if (!email && attrObjWorkEmail.operation === 'modify') email = ''; // value not included if blank    
                if (email == undefined) email = objWorkEmail.value; // original

                let phoneNumber = (attrObjWorkPhone.operation && attrObjWorkPhone.operation === 'delete') ? '' : attrObjWorkPhone.value;
                if (!phoneNumber && attrObjWorkPhone.operation === 'modify') phoneNumber = ''; // value not included if blank    
                if (phoneNumber == undefined) phoneNumber = objWorkPhone.value; // original

                let company = (attrObjCompanyEntitlement.operation && attrObjCompanyEntitlement.operation === 'delete') ? '' : attrObjCompanyEntitlement.value;
                if (!company && attrObjCompanyEntitlement.operation === 'modify') company = ''; // value not included if blank    
                if (company == undefined) company = objCompanyEntitlement.value; // original

                var soapRequest = {
                    "user": {
                        "userID": id,
                        "password": (clearedObj.password === '') ? '' : attrObj.password || userObj.password,
                        "firstName": (clearedObj.name.givenName === '') ? '' : attrObj.name.givenName || userObj.name.givenName,
                        "lastName": (clearedObj.name.familyName === '') ? '' : attrObj.name.familyName || userObj.name.familyName,
                        "displayName": (clearedObj.name.formatted === '') ? '' : attrObj.name.formatted || userObj.name.formatted,
                        "emailAddress": email,
                        "phoneNumber": phoneNumber,
                        "company": company,
                        "title": (clearedObj.title === '') ? '' : attrObj.title || userObj.title
                    }
                };

                serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.modifyUser()
                    scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
                    if (err) return callback(err);
                    else if (!result.return) {
                        scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                        var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                        err.name = 'NoResult';
                        return callback(err);
                    }
                    scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
                    callback(null);
                });
            });
        }
    });
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
//==========================================
scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
    var action = 'getGroup'
    scimgateway.logger.debug(`${pluginName} handling event "getGroup" group displayName=${displayName} attributes=${attributes}`);
    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var soapRequest = { "groupID": displayName };
        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.lookupGroup()
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} request: ${serviceClient.lastRequest}`);
            if (err) return callback(err);
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
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
// retrieve all users for a spesific group WHEN:
// "user member of group" - CA IM default scim endpoint config
// Group having multivalue attribute members containing userName
// 
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// id         = user id (eg. bjensen)
// attributes = attributes to be returned in callback (we only return the name of groups - displayName and current user as member)
// startIndex = Pagination - The 1-based index of the first result in the current set of search results
// count      = Pagination - Number of elements to be returned in the current set of search results
// callback   = Resources array to be filled with objects containing groups with current user as member to be returned
//      e.g [{"displayName":"Admins","members": [{ "value": bjensen}]}, {"displayName":"Employees", "members": [{ "value": bjensen}]}]
//
// If endpoint supports paging: totalResults shold be set to the total numbers of elements (group members) at endpoint.
//
// If we do not support groups (or "user member of group"), callback(null, []) with no additional code lines
//==========================================
scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
    var action = 'getGroupMembers'
    scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
    var ret = {
        "Resources": [],
        "totalResults": null
    };

    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var soapRequest = { sql: "SELECT * FROM Groups" };
        serviceClient[config[action]['method']](soapRequest, function (err, result, body) { // serviceClient.searchGroup()
            if (err) return callback(err);
            else if (!result) return callback(null, ret); // no groups
            else if (!result.return) {
                scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} response: ${JSON.stringify(result)}`);
                var err = new Error(`${action} ${config[action]['method']} : Got empty response on soap request: ${soapRequest}`);
                err.name = 'NoResult';
                return callback(err);
            }
            scimgateway.logger.debug(`${pluginName} ${action} ${config[action]['method']} result: ${JSON.stringify(result)}`);
            result.return.forEach(function (element) {
                if (Array.isArray(element.members)) {
                    element.members.forEach(function (el) {
                        if (el === id) { //user is member of group
                            var userGroup = {
                                "displayName": element.groupID, // displayName is mandatory
                                "members": [{ "value": el }]    // only includes current user (not all members)
                            }
                            ret.Resources.push(userGroup);
                        }
                    });
                }
            });
            callback(null, ret);
        });
    });
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
// => NOT used by plugin-forwardinc
//==========================================
scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    var action = 'getGroupUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupName=${groupName} attributes=${attributes}`);
    var arrRet = [];
    callback(null, arrRet);
});


//==========================================
//           CREATE GROUP
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// groupObj   = group object containing groupattributes according to scim standard
//              groupObj.displayName contains group name
// callback   = null (OK) or error object
//==========================================
scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
    var action = 'createGroup';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`);

	// groupObj.displayName contains the group to be created
	// if supporting create group we need some endpoint logic here

    let err = new Error(`Create group is not supported by ${pluginName}`);
    return callback(err);
    
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
//==========================================
scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
    var action = 'modifyGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`);
    if (Array.isArray(members)) {
        getServiceClient(baseEntity, action, function (err, serviceClient) {
            if (err) return callback(err);
            members.forEach(function (el) {
                if (el.operation && el.operation === 'delete') { // delete member from group
                    var soapRequest = {
                        "groupID": id,
                        "userID": el.value
                    };
                    serviceClient.removeUserFromGroup(soapRequest, function (err, result, body) {

                        if (err) return callback(err);
                        else if (!result.return) {
                            scimgateway.logger.debug(`${pluginName} ${action} removeUserFromGroup response: ${JSON.stringify(result)}`);
                            var err = new Error(`${action} removeUserFromGroup : Got empty response on soap request: ${soapRequest}`);
                            err.name = 'NoResult';
                            return callback(err);
                        }
                        scimgateway.logger.debug(`${pluginName} ${action} removeUserFromGroup result: ${JSON.stringify(result)}`);
                        callback(null);
                    });
                }
                else { // add member to group
                    var soapRequest = {
                        "groupID": id,
                        "userID": el.value
                    };
                    serviceClient.assignUserToGroup(soapRequest, function (err, result, body) {
                        if (err) return callback(err);
                        else if (!result.return) {
                            scimgateway.logger.debug(`${pluginName} ${action} assignUserToGroup response: ${JSON.stringify(result)}`);
                            var err = new Error(`${action} assignUserToGroup : Got empty response on soap request: ${soapRequest}`);
                            return callback(err);
                        }
                        scimgateway.logger.debug(`${pluginName} ${action} assignUserToGroup result: ${JSON.stringify(result)}`);
                        callback(null);
                    });
                }
            });
        }); // getServiceClient
    } // if Array
    else callback(null);
});



var getServiceClient = function (baseEntity, action, callback) {
    var entityService = config[action]['service'];

    if (_serviceClient[baseEntity] && _serviceClient[baseEntity][entityService]) { // serviceClient already exist
        scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}][${entityService}]: Using existing client`);
        return callback(null, _serviceClient[baseEntity][entityService]);
    }

    scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}][${entityService}]: Client have to be created`);

    var urlToWsdl = null; // may be file system URL or http URL
    var serviceEndpoint = null;
    var client = null;

    if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity];
    /* uncomment if using baseEntity for client spesific configuration - endpoint.entity.<client>
    if (!client) {
        var err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`);
        return callback(err);
    }
    */

    if (!config[action]) {
        var err = new Error(`getServiceClient function called with invalid action definition: ${action}`);
        return callback(err);
    }
    //urlToWsdl = `${config.baseServiceEndpoint}/${entityService}?wsdl'; // http URL
    urlToWsdl = require('path').resolve(`${wsdlDir}/${entityService}.wsdl`); // file system URL
    serviceEndpoint = config.baseServiceEndpoint + '/' + entityService;

    var wsdlOptions = {};

    soap.createClient(urlToWsdl, wsdlOptions, function (err, serviceClient) {
        if (err) {
            if (err.message) var err = new Error(`createClient ${urlToWsdl} errorMessage: ${err.message}`);
            else var err = new Error(`createClient ${urlToWsdl} errorMessage: invalid service definition - wsdl maybe not found?`);
            return callback(err);
        }
        serviceClient.setSecurity(new soap.WSSecurity(endpointUsername, endpointPassword, { "passwordType": "PasswordText", "hasTimeStamp": false }))
        serviceClient.setEndpoint(serviceEndpoint); // https://FQDN/path/to/service (not needed if urToWsdl is url not file)

        /* Custom soap header example (not used in plugin-forwardinc)
        // Could be used instead of WSSecurity header
        // Could send a custom SOAP header with signed SAML assertion to a Security Token Service
        // for requesting a security token (or use signedAssertion as is)
        // Use getSamlAssertion function to get client spesific signedAssertion

         var customHeader = {
            "AutHeader": {
                "Source": "Example",
                "Context": {
                    "company": baseEntity,
                    "userid": config.entity[baseEntity].userId,
                    "credentials": new Buffer(signedAssertion).toString('base64') // base64 encoded signed assertion
                }
            }
        };       
        serviceClient.addSoapHeader(customHeader);
        */

        if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {};
        _serviceClient[baseEntity][entityService] = serviceClient; // serviceClient created
        callback(null, _serviceClient[baseEntity][entityService]);
    });
}


//
// Example on how to create a signed saml assertion
// Note, not used in plugin-forwardinc
//
// Prereq variable defintions:
// var saml11 = require('saml').Saml11;
// var fs = require('fs');
//
// saml module is alredy installed and included with scimgateway
//
var getSamlAssertion = function (baseEntity, callback) {
    scimgateway.logger.debug(`${pluginName} getSamlAssertion[${baseEntity}]`);
    if (!config.entity[baseEntity]) {
        var err = new Error(`getSamlAssertion[${baseEntity}] "entity.${baseEntity}" is missing in ${pluginName}.json`);
        return callback(err);
    }
    if (!config.entity[baseEntity].cert || !config.entity[baseEntity].key) {
        var err = new Error(`getSamlAssertion[${baseEntity}] "entity.${baseEntity}.cert" or "entity.${baseEntity}.key" is missing in ${pluginName}.json`);
        return callback(err);
    }
    var cert = `${configDir}/certs/${config.entity[baseEntity].cert}`;
    var key = `${configDir}/certs/${config.entity[baseEntity].key}`;
    var options = {
        "cert": fs.readFileSync(cert).toString('ascii'),
        "key": fs.readFileSync(key).toString('ascii'),
        "lifetimeInSeconds": 1800, // 30 minutes
        "issuer": 'urn:issuer',
        "nameIdentifier": 'urn:issuer',
        "attributes": {
            "ourNamespace/company": baseEntity,
            "ourNamespace/userId": config.entity[baseEntity].userId
        }
    };
    saml11.create(options, function (err, signedAssertion) {
        if (err) return callback(err);
        scimgateway.logger.debug(`${pluginName} getSecurityToken[${baseEntity}] saml11 signedAssertion: ${signedAssertion}`);
        callback(null, signedAssertion)
    });
}
