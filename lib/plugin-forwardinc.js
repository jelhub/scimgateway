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
// Email        %UE% (Emails, type=Work)                emails.work                     emailAddress
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.work               phoneNumber
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.company            company
//
//=================================================================================

'use strict';

var soap = require('soap');

var path = require('path');
var ScimGateway = null;
try {
    ScimGateway = require('scimgateway');
} catch (err) {
    ScimGateway = require('./scimgateway');
}
var scimgateway = new ScimGateway();
var pluginName = path.basename(__filename, '.js'); // current file prefix (config file must have the same prefix)
var configDir = path.join(__dirname, '..', 'config');
var configFile = path.join(`${configDir}`, `${pluginName}.json`);
var config = require(configFile).endpoint;

var wsdlDir = path.join(`${configDir}`, 'wsdls');
var endpointUsername = config.username;
var endpointPassword = scimgateway.getPassword('endpoint.password', configFile);

var _serviceClient = {};

var validScimAttr = [   // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
    "userName",         // userName is mandatory
    "active",           // active is mandatory
    "password",
    "name.givenName",
    "name.familyName",
    "name.formatted",
    "title",
    //"emails",         // accepts all multivalues for this key
    "emails.work",      // accepts multivalues if type value equal work (lowercase) 
    //"phoneNumbers",
    "phoneNumbers.work",
    //"entitlements"
    "entitlements.company"
];


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
                        "id": element.userID,
                        "externalId": element.userID
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
                    "id": element.groupID,
                    "externalId": element.groupID
                };
                ret.Resources.push(scimGroup);
            });

            callback(null, ret); // all explored groups

        }); // searchGroup
    }); // getServiceClient
});


scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
    var action = "getUser";
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`);
    getServiceClient(baseEntity, action, function (err, serviceClient) {
        if (err) return callback(err);
        var arrAttr = [];
        if (attributes) arrAttr = attributes.split(',');

        if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
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
                    "externalId": userName
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
                    "userName": userName,
                    "id": userName,
                    "externalId": userName,
                    "password": result.return.password,
                    "name": {
                        "givenName": result.return.firstName,
                        "familyName": result.return.lastName,
                        "formatted": result.return.displayName
                    },
                    "title": result.return.title,
                    "emails": (result.return.emailAddress) ? [{
                        "value": result.return.emailAddress,
                        "type": "work"
                    }] : null,
                    "phoneNumbers": (result.return.phoneNumber) ? [{
                        "value": result.return.phoneNumber,
                        "type": "work"
                    }] : null,
                    "entitlements": (result.return.company) ? [{
                        "value": result.return.company,
                        "type": "Company"
                    }] : null
                }
                callback(null, userObj);
            });
        } // else
    }); // getServiceClient
});


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
        if (!userObj.emails) userObj.emails = { "work": {} };
        if (!userObj.phoneNumbers) userObj.phoneNumbers = { "work": {} };
        if (!userObj.entitlements) userObj.entitlements = { "company": {} };

        var soapRequest = {
            "user": {
                "userID": userObj.userName,
                "password": userObj.password || null,
                "firstName": userObj.name.givenName || null,
                "lastName": userObj.name.familyName || null,
                "displayName": userObj.name.formatted || null,
                "title": userObj.title || null,
                "emailAddress": userObj.emails.work.value || null,
                "phoneNumber": userObj.phoneNumbers.work.value || null,
                "company": userObj.entitlements.company.value || null
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

                userObj = scimgateway.convertedScim(userObj); // multivalue array to none-array based on type
                for (let key1 in attrObj) {
                    if (typeof attrObj[key1] === 'object') { // name.familyName
                        for (let key2 in attrObj[key1]) {
                            userObj[key1][key2] = attrObj[key1][key2]
                        }
                    }
                    else userObj[key1] = attrObj[key1]; // merge modified attr into userObj
                }

                if (!userObj.name) userObj.name = {};
                if (!userObj.emails) userObj.emails = { "work": {} };
                if (!userObj.phoneNumbers) userObj.phoneNumbers = { "work": {} };
                if (!userObj.entitlements) userObj.entitlements = { "company": {} };

                var soapRequest = {
                    "user": {
                        "userID": id,
                        "password": userObj.password,
                        "firstName": userObj.name.givenName,
                        "lastName": userObj.name.familyName,
                        "displayName": userObj.name.formatted,
                        "emailAddress": userObj.emails.work.value,
                        "phoneNumber": userObj.phoneNumbers.work.value,
                        "company": userObj.entitlements.company.value,
                        "title": userObj.title
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
            retObj.externalId = result.return.groupID; // mandatory for Azure AD
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


scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    var action = 'getGroupUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupName=${groupName} attributes=${attributes}`);
    var arrRet = [];
    callback(null, arrRet);
});


scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
    var action = 'createGroup';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`);

    // groupObj.displayName contains the group to be created
    // if supporting create group we need some endpoint logic here

    let err = new Error(`Create group is not supported by ${pluginName}`);
    return callback(err);

});


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
