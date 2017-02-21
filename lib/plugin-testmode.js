//=================================================================================
// File:    plugin-testmode.js
//
// Author:  Jarle Elshaug
//
// Purpose: Example code showing how to build an endpoint plugin for the ScimGateway
//          - SCIM endpoint simulation (in-memory, no physical endpoint)
//          - Two predefined users
//          - Supporting explore, create, delete, modify and list users (including groups)
//
// Note:    Assign user to groups are supported, but groups to users are not supported
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// All attributes are supported, note multivalue "type" must be unique
//
//=================================================================================

'use strict';

var ScimGateway = require('scimgateway');
var scimgateway = new ScimGateway();
var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var testmodeusers = [];
var testmodegroups = [];
testmodeusers = scimgateway.testmodeusers;
testmodegroups = scimgateway.testmodegroups;

//
// plugins needs endpoint configuration, but not plugin-testmode
// plugin-testmode use in-memory emulation and therefore do not need any physical endpoint connetion 
// Here are some examples how to read endpoint settings defined in plugin configuration file
//
var configFile = __dirname + '/../config/' + pluginName + '.json';
var config = require(configFile).endpoint;
var endpointHost = config.host;
var endpointPort = config.port;
var endpointUsername = config.username;
var endpointPassword = scimgateway.getPassword('endpoint.password', configFile);

/*
scimgateway.logger.debug('endpointHost = ' + endpointHost);
scimgateway.logger.debug('endpointPort = ' + endpointPort);
scimgateway.logger.debug('endpointUsername = ' + endpointUsername);
scimgateway.logger.debug('endpointPassword = ' + endpointPassword);
*/

var validScimAttr = []; // empty array - all attrbutes are supported by endpoint

/*
var validScimAttr = [   // array containing scim attributes supported by our plugin code
    "userName",         // userName is mandatory
    "active",           // active is mandatory
    "password",
    "name.givenName",
    "name.middleName",
    "name.familyName",
    "name.formatted",
    "name.honorificPrefix",
    "name.honorificSuffix",
    "displayName",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "preferredLanguage",
    "locale",
    "timezone",
    "externalId",
    "x509Certificates.0",
    "emails",               //accepts all multivalues for this key

    "emails.[].type=home",  //accepts multivalues if type value equal home (lowercase)
    "emails.[].type=work",  //accepts multivalues if type value equal work (lowercase) 
      
    "phoneNumbers",         //accepts all multivalues for this key
    "ims",                  //accepts all multivalues for this key       
    "photos",               //accepts all multivalues for this key
    "addresses",            //accepts all multivalues for this key
    "entitlements",         //accepts all multivalues for this key
    "roles"                 //accepts all multivalues for this key
];
*/


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
//==========================================
scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
    var action = 'exploreUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    var ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    if (!startIndex && !count) { // client request without paging
        startIndex = 1;
        count = testmodeusers.length;
    }
    for (var index = startIndex - 1; index < testmodeusers.length && (index + 1 - startIndex) < count; ++index) {
        if (testmodeusers[index].id && testmodeusers[index].userName) {
            var scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName) - scimdef have both set to the same value
                "userName": testmodeusers[index].userName,
                "id": testmodeusers[index].id
            };
            ret.Resources.push(scimUser);
        }
    }

    ret.totalResults = testmodeusers.length; //not needed if client or endpoint do not support paging
    callback(null, ret); // all explored users
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
    scimgateway.logger.debug(pluginName + ' handling event "exploreGroups"');
    var ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };

    if (!startIndex && !count) { // client request without paging
        startIndex = 1;
        count = testmodegroups.length;
    }
    for (var index = startIndex - 1; index < testmodegroups.length && (index + 1 - startIndex) < count; ++index) {
        if (testmodegroups[index].id && testmodegroups[index].displayName) {
            var scimGroup = { //displayName and id is mandatory, note: we set id=displayName (scimdef have both set to the same value)
                "displayName": testmodegroups[index].displayName,
                "id": testmodegroups[index].id
            };
            ret.Resources.push(scimGroup);
        }
    }

    ret.totalResults = testmodegroups.length; //not needed if client or endpoint do not support paging
    callback(null, ret); // all explored groups
});


//==========================================
//             GET USER
//
// baseEntity = Optional, used when multiple endpoint is needed (defined in base url e.g. <baseurl>/client1 gives baseEntity=client1)
// userName   = user id (eg. bjensen)
// attributes = scim attributes to be returned in callback. If no attributes defined, all will be returned.
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
    var retObj = {};
    var userObj = testmodeusers.find(function (element) { // Verify user exist
        return element.userName === userName;
    });
    if (!userObj) {
        var err = new Error('Could not find user with userName ' + userName);
        return callback(err);
    }
    if (!attributes)
        return callback(null, userObj) // user with all attributes
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
            }
            else if (arrAttributes[i] === 'password') { } // not returning password (normally not included in attributes)
            else retObj[arrAttributes[i]] = userObj[arrAttributes[i]]
        }
        callback(null, retObj);
    }
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
    var notValid = scimgateway.notValidAttributes(userObj, validScimAttr); // We should check for unsupported endpoint attributes
    if (notValid) {
        var err = new Error(`unsupported scim attributes: ${notValid} `
            + `(supporting only these attributes: ${validScimAttr.toString()})`
        );
        return callback(err);
    }
    userObj.id = userObj.userName; //for testmode-plugin (scim endpoint) id is mandatory and set to userName
    try {
        testmodeusers.push(userObj);
    } catch (err) {
        return callback(err);
    }
    callback(null);
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
    var userObj = testmodeusers.find(function (element, index) {
        if (element.id === id) {
            testmodeusers.splice(index, 1); // delete user
            return true;
        }
        else return false;
    });
    if (!userObj) {
        var err = new Error('Failed to delete user with id=' + id);
        return callback(err);
    }
    else {
        callback(null);
    }
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
    var notValid = scimgateway.notValidAttributes(attrObj, validScimAttr); // We should check for unsupported endpoint attributes
    if (notValid) {
        var err = new Error(`unsupported scim attributes: ${notValid} `
            + `(supporting only these attributes: ${validScimAttr.toString()})`
        );
        return callback(err);
    }

    var userObj = testmodeusers.find(function (element) {
        if (element.id === id) return true;
        else return false;
    });

    if (!userObj) {
        var err = new Error(`Failed to find user with id=${id}`);
        return callback(err);
    }
    else {
        var arrUser = [];
        arrUser = userObj;
        for (var key in attrObj) {
            //Special handling for multivalue attributes (arrays) eg. mail/phonenumber
            if (Array.isArray(attrObj[key])) {
                attrObj[key].forEach(function (el) {
                    //
                    // Create multivalue
                    // (using modify if type exist)
                    //
                    if (el.operation === 'create') {
                        delete el['operation'];
                        if (!arrUser[key]) arrUser[key] = [];
                        var found = arrUser[key].find(function (e, i) {
                            if (e.type === el.type && key !== 'groups') { // groups always create
                                arrUser[key][i] = el; //modify instead of create - we want to type to be unique
                                return true;
                            }
                            else return false;
                        });
                        if (!found) arrUser[key].push(el); // create
                    }
                    //
                    // Delete multivalue
                    //
                    else if (el.operation === 'delete') {
                        delete el['operation'];
                        arrUser[key].find(function (e, i) {
                            if ((e.type === el.type) && el.type) {
                                arrUser[key].splice(i, 1); //delete
                                if (arrUser[key].length < 1) delete arrUser[key];
                                return true;
                            }
                            if ((e.value === el.value) && el.value) { // groups
                                arrUser[key].splice(i, 1); //delete
                                if (arrUser[key].length < 1) delete arrUser[key];
                                return true;
                            }
                            else return false;
                        });
                    }
                    //
                    // Modify multivalue
                    //
                    else if (el.operation === 'modify') {
                        delete el['operator'];
                        arrUser[key].find(function (e, i) {
                            if (e.type === el.type) {
                                arrUser[key][i] = el;
                                return true;
                            }
                            else return false;
                        });
                    }
                });
            }
            else {
                //None multi value attribute
                if (typeof (attrObj[key]) !== 'object') arrUser[key] = attrObj[key];
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
                            var value = attrObj[key][sub];
                            arrUser[key][sub] = value;
                        }
                    }
                }
            }
        }
        callback(null);
    }
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
    scimgateway.logger.debug(pluginName + ' handling event "getGroup" group displayName=' + displayName + ' attributes=' + attributes);
    var retObj = {};
    var groupObj = testmodegroups.find(function (element) { // Verify group exist
        return element.displayName === displayName;
    });
    if (!groupObj) {
        var err = new Error('Could not find group with displayName ' + displayName);
        return callback(err);
    }
    else {
        retObj.displayName = groupObj.displayName; // displayName is mandatory
        retObj.id = groupObj.id;
        retObj.members = groupObj.members; // comment out this line if using "users are member of group"
    }

    callback(null, retObj)
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
// callback   = Resources array to be filled with objects containing groups with current user as member to be returned 
//      e.g [{"displayName":"Admins","members": [{ "value": bjensen}]}, {"displayName":"Employees", "members": [{ "value": bjensen}]}]
//
// If endpoint supports paging: totalResults shold be set to the total numbers of elements (group members) at endpoint.
//
// If we do not support groups (or "user member of group"), callback(null, []) with no additional code lines
//==========================================
scimgateway.on('getGroupMembers', function (baseEntity, id, attributes, startIndex, count, callback) {
    var action = 'getGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" user id=${id} attributes=${attributes}`);
    var ret = {
        "Resources": [],
        "totalResults": null
    };

    if (!startIndex && !count) { // client request without paging
        startIndex = 1;
        count = 9999999;
    }
    var i = 0;
    var j = 0;
    // find all groups user is member of
    testmodegroups.forEach(function (el) {
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
//==========================================
scimgateway.on('getGroupUsers', function (baseEntity, groupName, attributes, callback) {
    scimgateway.logger.debug(pluginName + ' handling event "getGroupUsers" groupName=' + groupName + ' attributes=' + attributes);
    var arrRet = [];
    for (var key in testmodeusers) {
        if (testmodeusers[key]['groups']) {
            var groupFound = testmodeusers[key]['groups'].find(function (element) {
                if (element.value === groupName) return true;
                else return false;
            });
            if (groupFound) arrRet.push({ "userName": testmodeusers[key].userName })
        }
    }
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
    scimgateway.logger.debug(pluginName + ' handling event "modifyGroupMembers" id=' + id + ' members=' + JSON.stringify(members));
    var groupObj = testmodegroups.find(function (element) {
        if (element.id === id) return true;
        else return false;
    });
    if (!groupObj) {
        var err = new Error('Failed to find group with id=' + id);
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
    callback(null);
});
