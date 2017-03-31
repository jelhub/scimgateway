//=================================================================================
// File:    plugin-restful.js
//
// Author:  Jarle Elshaug
//
// Purpose: REST Webservice user-provisioning using REST endpoint "testmode"
//
// Prereq:  plugin-testmode is up and running
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                            Endpoint
// -----------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        userName
// Suspended     -                                      active                          active
// Password     %P%                                     password                        password
// First Name   %UF%                                    name.givenName                  name.givenName
// Last Name    %UL%                                    name.familyName                 name.familyName
// Full Name    %UN%                                    name.formatted                  name.formatted
// Job title    %UT%                                    title                           title
// Email        %UE% (Emails, type=Work)                emails.work                     emails [type eq work] 
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.work               phoneNumbers [type eq work]
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.company            entitlements [type eq company]
//
//=================================================================================

'use strict';

const soap = require('soap');
const http = require('http');
const https = require('https');
const url = require('url');
const querystring = require('querystring');

const path = require('path');
let ScimGateway = null;
try {
    ScimGateway = require('scimgateway');
} catch (err) {
    ScimGateway = require('./scimgateway');
}
let scimgateway = new ScimGateway();
let pluginName = path.basename(__filename, '.js'); // current file prefix (config file must have the same prefix)
let configDir = path.join(__dirname, '..', 'config');
let configFile = path.join(`${configDir}`, `${pluginName}.json`);
let config = require(configFile).endpoint;
let validScimAttr = [   // array containing scim attributes supported by our plugin code. Empty array - all attrbutes are supported by endpoint
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

//let endpointUsername = config.username;
//let endpointPassword = scimgateway.getPassword('endpoint.password', configFile);
let _serviceClient = {};


scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
    let action = 'exploreUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    let ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    let request = {
        "attributes": "userName"
    }

    doRequest(baseEntity, '/Users', 'GET', request, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        else if (!result.Resources) {
            let err = new Error(`${action}: Got empty response on REST request`);
            return callback(err);
        }

        if (!startIndex && !count) { // client request without paging
            startIndex = 1;
            count = result.Resources.length;
        }
        for (let index = startIndex - 1; index < result.Resources.length && (index + 1 - startIndex) < count; ++index) {
            if (result.Resources[index].id && result.Resources[index].userName) {
                let scimUser = { // userName and id is mandatory, note: we set id=userName
                    "userName": result.Resources[index].userName,
                    "id": result.Resources[index].id,
                    "externalId": result.Resources[index].userName
                };
                ret.Resources.push(scimUser);
            }
        }
        //not needed if client or endpoint do not support paging
        ret.totalResults = result.Resources.length;
        ret.startIndex = startIndex;

        callback(null, ret); // all explored users

    }); // doRequest
});


scimgateway.on('exploreGroups', function (baseEntity, startIndex, count, callback) {
    let action = 'exploreGroups';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    let ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    let request = {
        "attributes": "displayName"
    }

    doRequest(baseEntity, '/Groups', 'GET', querystring.stringify(request), function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        else if (!result.Resources) {
            let err = new Error(`${action}: Got empty response on REST request`);
            return callback(err);
        }

        if (!startIndex && !count) { // client request without paging
            startIndex = 1;
            count = result.Resources.length;
        }
        for (let index = startIndex - 1; index < result.Resources.length && (index + 1 - startIndex) < count; ++index) {
            if (result.Resources[index].id && result.Resources[index].displayName) {
                let scimGroup = { //displayName and id is mandatory, note: we set id=displayName
                    "displayName": result.Resources[index].displayName,
                    "id": result.Resources[index].id,
                    "externalId": result.Resources[index].displayName
                };
                ret.Resources.push(scimGroup);
            }
        }
        //not needed if client or endpoint do not support paging
        ret.totalResults = result.Resources.length;
        ret.startIndex = startIndex;

        callback(null, ret); // all explored users

    }); // doRequest

});


scimgateway.on('getUser', function (baseEntity, userName, attributes, callback) {
    let action = "getUser";
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`);

    let arrAttr = [];
    if (attributes) arrAttr = attributes.split(',');

    if (attributes && arrAttr.length < 3) { // userName and/or id - check if user exist
        let request = {
            "filter": `userName eq "${userName}"`,
            "attributes": "userName"
        }

        doRequest(baseEntity, '/Users', 'GET', request, function (err, result) {
            scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
            if (err) return callback(err);
            else if (!result.Resources) {
                let err = new Error(`${action}: Got empty response on REST request`);
                return callback(err);
            }

            let userObj = result.Resources.find(function (element) { // Verify user exist
                return element.userName === userName;
            });
            if (!userObj) {
                let err = new Error('Could not find user with userName ' + userName);
                return callback(err);
            }
            let retObj = {
                "id": userName,
                "userName": userName,
                "externalId": userName
            };

            callback(null, retObj); // return user found

        }); // doRequest

    }
    else { // all endpoint supported attributes
        let request = {
            "filter": `userName eq "${userName}"`,
            "attributes": "userName,active,name.givenName,name.familyName,name.formatted,title,emails,phoneNumbers,entitlements"
        }

        doRequest(baseEntity, '/Users', 'GET', request, function (err, result) {
            scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
            if (err) return callback(err);
            else if (!result.Resources) {
                let err = new Error(`${action}: Got empty response on REST request`);
                return callback(err);
            }

            let userObj = result.Resources.find(function (element) { // Verify user exist
                return element.userName === userName;
            });
            if (!userObj) {
                let err = new Error('Could not find user with userName ' + userName);
                return callback(err);
            }

            if (!userObj.name) userObj.name = {};
            if (!userObj.emails) userObj.emails = [{}];
            if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}];
            if (!userObj.entitlements) userObj.entitlements = [{}];

            let objWorkEmail = scimgateway.getArrayObject(userObj, 'emails', 'work');
            let objWorkPhone = scimgateway.getArrayObject(userObj, 'phoneNumbers', 'work');
            let objCompanyEntitlement = scimgateway.getArrayObject(userObj, 'entitlements', 'company');

            let arrEmail = [];
            let arrPhone = [];
            let arrEntitlement = [];
            if (objWorkEmail) arrEmail.push(objWorkEmail);
            else arrEmail = null;
            if (objWorkPhone) arrPhone.push(objWorkPhone);
            else arrPhone = null;
            if (objCompanyEntitlement) arrEntitlement.push(objCompanyEntitlement);
            else arrEntitlement = null;

            let retObj = {
                "userName": userObj.userName,
                "externalId": userObj.userName,
                "active": userObj.active,
                "name": {
                    "givenName": userObj.name.givenName || "",
                    "familyName": userObj.name.familyName || "",
                    "formatted": userObj.name.formatted || ""
                },
                "title": userObj.title,
                "emails": arrEmail,
                "phoneNumbers": arrPhone,
                "entitlements": arrEntitlement
            };

            callback(null, retObj); // return user found

        }); // doRequest

    } // else

});


scimgateway.on('createUser', function (baseEntity, userObj, callback) {
    let action = 'createUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userObj=${JSON.stringify(userObj)}`);

    let notValid = scimgateway.notValidAttributes(userObj, validScimAttr);
    if (notValid) {
        let err = new Error(`unsupported scim attributes: ${notValid} `
            + `(supporting only these attributes: ${validScimAttr.toString()})`
        );
        return callback(err);
    }

    if (!userObj.name) userObj.name = {};
    if (!userObj.emails) userObj.emails = { "work": {} };
    if (!userObj.phoneNumbers) userObj.phoneNumbers = { "work": {} };
    if (!userObj.entitlements) userObj.entitlements = { "company": {} };

    let arrEmail = [];
    let arrPhone = [];
    let arrEntitlement = [];
    if (userObj.emails.work.value) arrEmail.push(userObj.emails.work);
    if (userObj.phoneNumbers.work.value) arrPhone.push(userObj.phoneNumbers.work);
    if (userObj.entitlements.company.value) arrEntitlement.push(userObj.entitlements.company);

    let body = {
        "userName": userObj.userName,
        "active": userObj.active || true,
        "password": userObj.password || null,
        "name": {
            "givenName": userObj.name.givenName || null,
            "familyName": userObj.name.familyName || null,
            "formatted": userObj.name.formatted || null
        },
        "title": userObj.title || "",
        "emails": (arrEmail.length > 0) ? arrEmail : null,
        "phoneNumbers": (arrPhone.length > 0) ? arrPhone : null,
        "entitlements": (arrEntitlement.length > 0) ? arrEntitlement : null
    }

    doRequest(baseEntity, '/Users', 'POST', body, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    }); // doRequest

});


scimgateway.on('deleteUser', function (baseEntity, id, callback) {
    let action = 'deleteUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id}`);

    doRequest(baseEntity, `/Users/${id}`, 'DELETE', null, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    }); // doRequest

});


scimgateway.on('modifyUser', function (baseEntity, id, attrObj, callback) {
    let action = 'modifyUser';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} attrObj=${JSON.stringify(attrObj)}`);

    let notValid = scimgateway.notValidAttributes(attrObj, validScimAttr);
    if (notValid) {
        let err = new Error(`unsupported scim attributes: ${notValid} `
            + `(supporting only these attributes: ${validScimAttr.toString()})`
        );
        return callback(err);
    }

    if (!attrObj.name) attrObj.name = {};
    if (!attrObj.emails) attrObj.emails = {};
    if (!attrObj.phoneNumbers) attrObj.phoneNumbers = {};
    if (!attrObj.entitlements) attrObj.entitlements = {};

    let arrEmail = [];
    let arrPhone = [];
    let arrEntitlement = [];
    if (attrObj.emails.work) arrEmail.push(attrObj.emails.work);
    if (attrObj.phoneNumbers.work) arrPhone.push(attrObj.phoneNumbers.work);
    if (attrObj.entitlements.company) arrEntitlement.push(attrObj.entitlements.company);

    let body = { "userName": id };
    if (attrObj.active == true) body.active = true;
    else if (attrObj.active == false) body.active = false;

    if (attrObj.password) body.password = attrObj.password;
    
    if (attrObj.name.givenName || attrObj.name.givenName === '') {
        if (!body.name) body.name = {};
        body.name.givenName = attrObj.name.givenName;
    }
    if (attrObj.name.familyName || attrObj.name.familyName === '') {
        if (!body.name) body.name = {};
        body.name.familyName = attrObj.name.familyName;
    }
    if (attrObj.name.formatted || attrObj.name.formatted === '') {
        if (!body.name) body.name = {};
        body.name.formatted = attrObj.name.formatted;
    }
    if (attrObj.title || attrObj.title === '') {
        body.title = attrObj.title;
    }
    if (arrEmail.length > 0) {
        body.emails = arrEmail;
    }
    if (arrPhone.length > 0) {
        body.phoneNumbers = arrPhone;
    }
    if (arrEntitlement.length > 0) {
        body.entitlements = arrEntitlement;
    }

    doRequest(baseEntity, `/Users/${id}`, 'PATCH', body, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    }); // doRequest

});


scimgateway.on('getGroup', function (baseEntity, displayName, attributes, callback) {
    let action = 'getGroup'
    scimgateway.logger.debug(`${pluginName} handling event "getGroup" group displayName=${displayName} attributes=${attributes}`);


    // GET = /Groups?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName
    let request = {
        "filter": `displayName eq "${displayName}"`,
        "attributes": attributes
    }

    doRequest(baseEntity, '/Groups', 'GET', request, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        else if (!result.Resources) {
            let err = new Error(`${action}: Got empty response on REST request`);
            return callback(err);
        }

        let retObj = {};

        if (result.Resources.length === 1) {
            let grp = result.Resources[0];
            retObj.displayName = grp.displayName; // displayName is mandatory
            retObj.id = grp.id;
            retObj.externalId = grp.displayName; // mandatory for Azure AD
            if (Array.isArray(grp.members)) {
                retObj.members = [];
                grp.members.forEach(function (el) {
                    retObj.members.push({ "value": el.value });
                });
            }
        }
        callback(null, retObj);
    });
});


scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
    let action = 'getGroupMembers'
    scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
    let ret = {
        "Resources": [],
        "totalResults": null
    };

    //GET = /Groups?filter=members.value eq "bjensen"&attributes=members.value,displayName
    let request = {
        "filter": `members.value eq "${id}"`,
        "attributes": attributes
    }

    doRequest(baseEntity, '/Groups', 'GET', request, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        else if (!result.Resources) {
            let err = new Error(`${action}: Got empty response on REST request`);
            return callback(err);
        }

        result.Resources.forEach(function (element) {
            if (Array.isArray(element.members)) {
                element.members.forEach(function (el) {
                    if (el.value === id) { // user is member of group
                        let userGroup = {
                            "displayName": element.displayName,   // displayName is mandatory
                            "members": [{ "value": el.value }]    // only includes current user
                        }
                        ret.Resources.push(userGroup);
                    }
                });
            }
        });
        callback(null, ret);
    });
});


scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    let action = 'getGroupUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupName=${groupName} attributes=${attributes}`);
    let arrRet = [];
    callback(null, arrRet);
});


scimgateway.on('createGroup', function (baseEntity, groupObj, callback) {
    let action = 'createGroup';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" groupObj=${JSON.stringify(groupObj)}`);

    let body = {
        "displayName": groupObj.displayName // group name to be created
    }

    doRequest(baseEntity, '/Groups', 'POST', body, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    }); // doRequest

});


scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
    let action = 'modifyGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`);
    let body = { "members": [] };
    if (Array.isArray(members)) {
        members.forEach(function (el) {
            if (el.operation && el.operation === 'delete') { // delete member from group
                // PATCH = /Groups/Admins Body = {"members":[{"operation":"delete","value":"bjensen"}]}
                body.members.push({ "operation": "delete", "value": el.value })
            }
            else { // add member to group/
                // PATCH = /Groups/Admins Body = {"members":[{"value":"bjensen"}]
                body.members.push({ "value": el.value })
            }
        });
    } // if Array

    doRequest(baseEntity, `/Groups/${id}`, 'PATCH', body, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    });

});


//
// getServiceClient - returns connection parameters needed
//
let getServiceClient = function (baseEntity, callback) {

    if (_serviceClient[baseEntity]) { // serviceClient already exist
        scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Using existing client`);
        return callback(null, _serviceClient[baseEntity]);
    }
    scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Client have to be created`);
    let client = null;
    if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity];
    if (!client) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`);
        return callback(err);
    }

    let param = {
        "host": url.parse(config.entity[baseEntity].baseUrl).hostname,
        "port": url.parse(config.entity[baseEntity].baseUrl).port,
        "protocol": url.parse(config.entity[baseEntity].baseUrl).protocol.slice(0, -1), // remove trailing ":"
        "auth": 'Basic ' + new Buffer(`${config.entity[baseEntity].username}:${scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)}`).toString('base64')
    };

    if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {};
    _serviceClient[baseEntity] = param; // serviceClient created
    callback(null, _serviceClient[baseEntity]);
}



//
// doRequest - execute REST service
//
let doRequest = function (baseEntity, endpoint, method, data, callback) {
    getServiceClient(baseEntity, function (err, serviceClient) { // e.g serviceClient = {host: "localhost, port: "8880", auth: 'Basic' + new Buffer("gwadmin:password").toString('base64')}
        if (err) return callback(err);
        let dataString = '';
        let headers = {};

        if (method == 'GET') {
            if (typeof (data) === 'string') dataString = data;
            else dataString = querystring.stringify(data) // JSON to query string syntax + URL encoded - preferred method
            endpoint += '?' + dataString;
            headers = {
                "Authorization": serviceClient.auth     // not using proxy
                //"Proxy-Authorization": auth           // using proxy
            }
        }
        else {
            dataString = JSON.stringify(data);
            headers = {
                "Authorization": serviceClient.auth,    // not using proxy
                //"Proxy-Authorization": auth           // using proxy
                'Content-Type': 'application/json',
                'Content-Length': dataString.length
            };
        }

        let options = {
            "host": serviceClient.host,
            "port": serviceClient.port,
            "path": endpoint,
            "method": method,
            "headers": headers
        };

        let reqType = (serviceClient.protocol === 'https') ? https.request : http.request;
        let req = reqType(options, function (res) {
            let responseString = '';
            res.setEncoding('utf-8');

            req.on('error', function (error) {
                callback(error)
            });

            res.on('data', function (data) {
                responseString += data;
            });

            res.on('end', function () {
                if (res.statusCode < 200 || res.statusCode > 299) {
                    let err = new Error(`Error message: ${res.statusMessage} - ${responseString}`);
                    return callback(err);
                }
                if (responseString.length < 1) callback(null, null)
                else callback(null, JSON.parse(responseString));
            });
        });

        req.write(dataString);
        req.end();
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] request: ${req.agent.protocol}//${req._headers.host} ${req.method} ${req.path}`);

    }); // getServiceClient 
}
