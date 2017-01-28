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
// Email        %UE% (Emails, type=Work)                emails.[].type=work             emails.[].type=work
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.[].type=work       phoneNumbers.[].type=work
// Company      %UCOMP% (Entitlements, type=Company)    entitlements.[].type=company    entitlements.[].type=company
//
//=================================================================================

'use strict';

var ScimGateway = require('scimgateway');
var scimgateway = new ScimGateway();

var http = require('http');
var https = require('https');
var url = require('url');
var querystring = require('querystring');

var soap = require('soap');
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var configDir = __dirname + '/../config';
var configFile = configDir + '/' + pluginName + '.json';
var config = require(configFile).endpoint;
var wsdlDir = configDir + '/wsdls';

//var endpointUsername = config.username;
//var endpointPassword = scimgateway.getPassword('endpoint.password', configFile);

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
//==========================================
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
                    "id": result.Resources[index].id
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
                    "id": result.Resources[index].id
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
    let action = "getUser";
    scimgateway.logger.debug(`${pluginName} handling event "${action}" userName=${userName} attributes=${attributes}`);
    let arrAttr = attributes.split(',');

    if (arrAttr.length < 3) { // userName and/or id - check if user exist
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
                var err = new Error('Could not find user with userName ' + userName);
                return callback(err);
            }
            let retObj = {
                "id": userName,
                "userName": userName
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
                var err = new Error('Could not find user with userName ' + userName);
                return callback(err);
            }

            if (!userObj.name) userObj.name = {};
            if (!userObj.emails) userObj.emails = [{}];
            if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}];
            if (!userObj.entitlements) userObj.entitlements = [{}];

            let emailWork = userObj.emails.find(function (element) {
                if (element.type) {
                    element.type = element.type.toLowerCase();
                    return element.type === 'work';
                }
            });
            let phoneWork = userObj.phoneNumbers.find(function (element) {
                if (element.type) {
                    element.type = element.type.toLowerCase();
                    return element.type === 'work';
                }
            });
            let entitleCompany = userObj.entitlements.find(function (element) {
                if (element.type) {
                    element.type = element.type.toLowerCase();
                    return element.type === 'company';
                }
            });
            let arrEmail = [];
            let arrPhone = [];
            let arrEntitlement = [];
            if (emailWork) arrEmail.push(emailWork);
            else arrEmail = null;
            if (phoneWork) arrPhone.push(phoneWork);
            else arrPhone = null;
            if (entitleCompany) arrEntitlement.push(entitleCompany);
            else arrEntitlement = null;

            let retObj = {
                "id": userObj.userName,
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


//==========================================
//           CREATE USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// userObj    = user object containing userattributes according to scim standard
// callback   = null (OK) or error object
//==========================================
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
    if (!userObj.emails) userObj.emails = [{}];
    if (!userObj.phoneNumbers) userObj.phoneNumbers = [{}];
    if (!userObj.entitlements) userObj.entitlements = [{}];

    let emailWork = userObj.emails.find(function (element) {
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'work';
        }
    });
    let phoneWork = userObj.phoneNumbers.find(function (element) {
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'work';
        }
    });
    let entitleCompany = userObj.entitlements.find(function (element) {
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'company';
        }
    });
    let arrEmail = [];
    let arrPhone = [];
    let arrEntitlement = [];
    if (emailWork) arrEmail.push(emailWork);
    if (phoneWork) arrPhone.push(phoneWork);
    if (entitleCompany) arrEntitlement.push(entitleCompany);

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

    doRequest(baseEntity, `/Users/${id}`, 'DELETE', null, function (err, result) {
        scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
        if (err) return callback(err);
        callback(null);
    }); // doRequest

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
    if (!attrObj.emails) attrObj.emails = [{}];
    if (!attrObj.phoneNumbers) attrObj.phoneNumbers = [{}];
    if (!attrObj.entitlements) attrObj.entitlements = [{}];

    let clearedObj = {}; // include cleared attributes, attrObj exampel: { meta: { attributes: [ 'name.givenName', 'title' ] } }
    clearedObj.name = {};
    if (attrObj.meta && attrObj.meta.attributes && Array.isArray(attrObj.meta.attributes)) {
        attrObj.meta.attributes.forEach(function (element) {
            var arrSub = element.split('.');
            if (arrSub.length === 2) clearedObj[arrSub[0]][arrSub[1]] = ''; // eg. name.givenName
            else clearedObj[element] = '';
        });
    }

    let emailWork = attrObj.emails.find(function (element) {
        //"emails":[{"operation":"delete","type":"work","value":"bjensen@example.com"}]
        //"emails":[{type":"work","value":"bjensen@example.com"}]
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'work';
        }
    });

    let phoneWork = attrObj.phoneNumbers.find(function (element) {
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'work';
        }
    });
    let entitleCompany = attrObj.entitlements.find(function (element) {
        if (element.type) {
            element.type = element.type.toLowerCase();
            return element.type === 'company';
        }
    });
    let arrEmail = [];
    let arrPhone = [];
    let arrEntitlement = [];
    if (emailWork) arrEmail.push(emailWork);
    if (phoneWork) arrPhone.push(phoneWork);
    if (entitleCompany) arrEntitlement.push(entitleCompany);

    let body = { "userName": id };
    if (attrObj.active == true) body.active = true;
    else if (attrObj.active == false) body.active = false;

    if (clearedObj.password === '' || attrObj.password) {
        body.password = (clearedObj.password === '') ? '' : attrObj.password;
    }
    if (clearedObj.name.givenName === '' || attrObj.name.givenName) {
        if (!body.name) body.name = {};
        body.name.givenName = (clearedObj.name.givenName === '') ? '' : attrObj.name.givenName;
    }
    if (clearedObj.name.familyName === '' || attrObj.name.familyName) {
        if (!body.name) body.name = {};
        body.name.familyName = (clearedObj.name.familyName === '') ? '' : attrObj.name.familyName;
    }
    if (clearedObj.name.formatted === '' || attrObj.name.formatted) {
        if (!body.name) body.name = {};
        body.name.formatted = (clearedObj.name.formatted === '') ? '' : attrObj.name.formatted;
    }
    if (clearedObj.title === '' || attrObj.title) {
        body.title = (clearedObj.title === '') ? '' : attrObj.title;
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

        var retObj = {};

        if (result.Resources.length === 1) {
            let grp = result.Resources[0];
            retObj.displayName = grp.displayName; // displayName is mandatory
            retObj.id = grp.id;
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
//==========================================
scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
    var action = 'getGroupMembers'
    scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
    var ret = {
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
                        var userGroup = {
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
// => NOT used by plugin-restful
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
//==========================================
scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
    var action = 'modifyGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`);
    if (Array.isArray(members)) {

        members.forEach(function (el) {
            if (el.operation && el.operation === 'delete') { // delete member from group
                // PATCH = /Groups/Admins Body = {"members":[{"operation":"delete","value":"bjensen"}]}
                let body = {
                    "members": [{
                        "operation": "delete",
                        "value": el.value
                    }]
                }

                doRequest(baseEntity, `/Groups/${id}`, 'PATCH', body, function (err, result) {
                    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
                    if (err) return callback(err);
                    callback(null);
                });

            }
            else { // add member to group/
                // PATCH = /Groups/Admins Body = {"members":[{"value":"bjensen"}]
                let body = {
                    "members": [{
                        "value": el.value
                    }]
                }

                doRequest(baseEntity, `/Groups/${id}`, 'PATCH', body, function (err, result) {
                    scimgateway.logger.debug(`${pluginName} doRequest[${baseEntity}] response: ${JSON.stringify(result)}`);
                    if (err) return callback(err);
                    callback(null);
                });
            }
        });

    } // if Array
    else callback(null);
});


//
// getServiceClient - returns connection parameters needed
//
var getServiceClient = function (baseEntity, callback) {

    if (_serviceClient[baseEntity]) { // serviceClient already exist
        scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Using existing client`);
        return callback(null, _serviceClient[baseEntity]);
    }
    scimgateway.logger.debug(`${pluginName} getServiceClient[${baseEntity}]: Client have to be created`);
    var client = null;
    if (config.entity && config.entity[baseEntity]) client = config.entity[baseEntity];
    if (!client) {
        let err = new Error(`Base URL have baseEntity=${baseEntity}, and configuration file ${pluginName}.json is missing required baseEntity configuration for ${baseEntity}`);
        return callback(err);
    }

    var param = {
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
var doRequest = function (baseEntity, endpoint, method, data, callback) {
    getServiceClient(baseEntity, function (err, serviceClient) { // e.g serviceClient = {host: "localhost, port: "8880", auth: 'Basic' + new Buffer("gwadmin:password").toString('base64')}
        if (err) return callback(err);
        var dataString = '';
        var headers = {};

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

        var options = {
            "host": serviceClient.host,
            "port": serviceClient.port,
            "path": endpoint,
            "method": method,
            "headers": headers
        };

        var reqType = (serviceClient.protocol === 'https') ? https.request : http.request;
        var req = reqType(options, function (res) {
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
