//=================================================================================
// File:    plugin-mssql.js
//
// Author:  Jarle Elshaug
//
// Purpose: SQL user-provisioning
//
// Prereq:
// TABLE [dbo].[User](
// 	[UserID] [varchar](50) NOT NULL,
// 	[Enabled] [varchar](50) NULL,
// 	[Password] [varchar](50) NULL,
// 	[FirstName] [varchar](50) NULL,
// 	[MiddleName] [varchar](50) NULL,
// 	[LastName] [varchar](50) NULL,
// 	[Email] [varchar](50) NULL,
// 	[MobilePhone] [varchar](50) NULL
// )
//
// Supported attributes:
//
// GlobalUser   Template                                Scim                        Endpoint
// --------------------------------------------------------------------------------------------
// User name    %AC%                                    userName                        UserID
// Suspended    (auto included)                         active                          Enabled
// Password     %P%                                     password                        Password
// First Name   %UF%                                    name.givenName                  FirstName
// Middle Name  %UMN%                                   name.middleName                 MiddleName
// Last Name    %UL%                                    name.familyName                 LastName
// Email        %UE% (Emails, type=Work)                emails.[].type=work             Email
// Phone        %UP% (Phone Numbers, type=Work)         phoneNumbers.[].type=work       MobilePhone
//
//=================================================================================

'use strict';

var ScimGateway = require('scimgateway');
var scimgateway = new ScimGateway();

var Connection = require('tedious').Connection;
var Request = require('tedious').Request;

var pluginName = require('path').basename(__filename, '.js'); // current file prefix (config file must have same prefix)
var configDir = __dirname + '/../config';
var configFile = configDir + '/' + pluginName + '.json';
var config = require(configFile).endpoint;

var sqlPassword = scimgateway.getPassword('endpoint.connection.password', configFile);
config.connection.password = sqlPassword; // Connection using config.connection

var _serviceClient = {};

var validScimAttr = [   // array containing scim attributes supported by our plugin code
    "userName",         // userName is mandatory
    "active",           // active is mandatory
    "password",
    "name.givenName",
    "name.middleName",
    "name.familyName",
    //"emails",             // accepts all multivalues for this key
    "emails.[].type=work",  // accepts multivalues if type value equal work (lowercase) 
    //"phoneNumbers",
    "phoneNumbers.[].type=work",
    //"entitlements",
    "entitlements.[].type=company"
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
// => plugin-mssql pagination not implemented
//==========================================
scimgateway.on('exploreUsers', function (baseEntity, startIndex, count, callback) {
    let action = 'exploreUsers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}"`);
    let ret = { // itemsPerPage will be set by scimgateway
        "Resources": [],
        "totalResults": null
    };
    let connection = new Connection(config.connection);

    connection.on('connect', function (err) {
        if (err) {
            console.log(err.message)
            var err = new Error(`Explore-Users connect: MSSQL client connect error: ${err.message}`);
            return callback(err);
        }
        let sqlQuery = 'select UserID from [User]';
        let request = new Request(sqlQuery, function (err, rowCount, rows) {
            if (err) {
                connection.close();
                var err = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                return callback(err);
            }
            for (let row in rows) {
                let id = rows[row].UserID.value;
                let userName = rows[row].UserID.value;
                let scimUser = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
                    "userName": userName,
                    "id": id
                };
                ret.Resources.push(scimUser);
            }
            connection.close();
            callback(null, ret); // all explored users

        }); // request
        connection.execSql(request);

    }); // connection
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
// => plugin-mssql groups not implemented
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


    let connection = new Connection(config.connection);

    connection.on('connect', function (err) {
        if (err) {
            console.log(err.message)
            var err = new Error(`Explore-Users connect: MSSQL client connect error: ${err.message}`);
            return callback(err);
        }

        var arrAttr = attributes.split(',');
        if (arrAttr.length == 2) { // userName and id - user lookup
            let sqlQuery = `select UserID from [User] where UserID = '${userName}'`;
            let request = new Request(sqlQuery, function (err, rowCount, rows) {
                if (err) {
                    connection.close();
                    var err = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                    return callback(err);
                }
                if (rowCount == 1) {
                    let userObj = { // userName and id is mandatory, note: we set id=userName (because update user sends scim id and not userName)
                        "userName": rows[0].UserID.value,
                        "id": rows[0].UserID.value
                    };
                    connection.close();
                    callback(null, userObj);;
                } else {
                    var err = new Error('Get-User mssql.request: User not found sqlQuery = ' + sqlQuery);
                    connection.close();
                    return callback(err);
                }
            }); // request
            connection.execSql(request);

        }
        else { // all endpoint supported attributes
            let sqlQuery = `select UserID, Enabled, FirstName, MiddleName, LastName, Email, MobilePhone from [User] where UserID = '${userName}'`;
            let request = new Request(sqlQuery, function (err, rowCount, rows) {
                if (err) {
                    connection.close();
                    var err = new Error(`Explore-Users connect: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                    return callback(err);
                }
                if (rowCount == 1) {
                    let userObj = {
                        "userName": rows[0].UserID.value, // not needed
                        "id": rows[0].UserID.value,       // not needed
                        "active": rows[0].Enabled.value,
                        "name": {
                            "givenName": rows[0].FirstName.value || '',
                            "middleName": rows[0].MiddleName.value || '',
                            "familyName": rows[0].LastName.value || ''
                        },
                        "emails": [{
                            "value": rows[0].Email.value || '',
                            "type": "work"
                        }],
                        "phoneNumbers": [{
                            "value": rows[0].MobilePhone.value || '',
                            "type": "work"
                        }]
                    }
                    connection.close();
                    callback(null, userObj);;
                } else {
                    var err = new Error('Get-User mssql.request: User not found sqlQuery = ' + sqlQuery);
                    connection.close();
                    return callback(err);
                }
            }); // request
            connection.execSql(request);

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

    let objWorkPhone =  scimgateway.getArrayObject(attrObj, 'phoneNumbers', 'work') || {};
    let objWorkEmail =  scimgateway.getArrayObject(attrObj, 'emails', 'work') || {};

    let insert = {
        "UserID": `'${userObj.userName}'`,
        "Enabled": (userObj.active) ? `'${userObj.active}'` : null,
        "Password": (userObj.password) ? `'${userObj.password}'` : null,
        "FirstName": (userObj.name.givenName) ? `'${userObj.name.givenName}'` : null,
        "MiddleName": (userObj.name.middleName) ? `'${userObj.name.middleName}'` : null,
        "LastName": (userObj.name.familyName) ? `'${userObj.name.familyName}'` : null,
        "MobilePhone": (objWorkPhone.value) ? `'${objWorkPhone.value}'` : null,
        "Email": (objWorkEmail.value) ? `'${objWorkEmail.value}'` : null
    };

    let connection = new Connection(config.connection);

    connection.on('connect', function (err) {
        if (err) {
            console.log(err.message)
            var err = new Error(`Create-Users connect: MSSQL client connect error: ${err.message}`);
            return callback(err);
        }
        let sqlQuery = `insert into [User] (UserID, Enabled, Password, FirstName, MiddleName, LastName, Email, MobilePhone) 
                values (${insert.UserID}, ${insert.Enabled}, ${insert.Password}, ${insert.FirstName}, ${insert.MiddleName}, ${insert.LastName}, ${insert.Email}, ${insert.MobilePhone})`;

        let request = new Request(sqlQuery, function (err, rowCount, rows) {
            if (err) {
                connection.close();
                var err = new Error(`Create-Users: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                return callback(err);
            }
            connection.close();
            callback(null);
        }); // request
        connection.execSql(request);

    }); // connection


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

    let connection = new Connection(config.connection);

    connection.on('connect', function (err) {
        if (err) {
            console.log(err.message)
            var err = new Error(`Delete-User connect: MSSQL client connect error: ${err.message}`);
            return callback(err);
        }
        let sqlQuery = `delete from [User] where UserID = '${id}'`;
        let request = new Request(sqlQuery, function (err, rowCount, rows) {
            if (err) {
                connection.close();
                var err = new Error(`Delete-User: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                return callback(err);
            }
            connection.close();
            callback(null);

        }); // request
        connection.execSql(request);

    }); // connection

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

    var clearedObj = {}; // include cleared attributes, attrObj exampel: { meta: { attributes: [ 'name.givenName', 'title' ] } }
    clearedObj.name = {};
    if (attrObj.meta && attrObj.meta.attributes && Array.isArray(attrObj.meta.attributes)) {
        attrObj.meta.attributes.forEach(function (element) {
            var arrSub = element.split('.');
            if (arrSub.length === 2) clearedObj[arrSub[0]][arrSub[1]] = ''; // eg. name.givenName
            else clearedObj[element] = '';
        });
    }

    let sql = '';

    if (attrObj.active !== undefined) sql += `Enabled='${attrObj.active}',`;
    let password = (clearedObj.password === '') ? null : attrObj.password;
    if (password !== undefined) {
        if (password === null) sql += `Password=${password},`;
        else sql += `Password='${password}',`;
    }
    let firstName = (clearedObj.name.givenName === '') ? null : attrObj.name.givenName;
    if (firstName !== undefined) {
        if (firstName === null) sql += `FirstName=${firstName},`;
        else sql += `FirstName='${firstName}',`;
    }
    let middleName = (clearedObj.name.middleName === '') ? null : attrObj.name.middleName;
    if (middleName !== undefined) {
        if (middleName === null) sql += `MiddleName=${middleName},`;
        else sql += `MiddleName='${middleName}',`;
    }
    let lastName = (clearedObj.name.familyName === '') ? null : attrObj.name.familyName;
    if (lastName !== undefined) {
        if (lastName === null) sql += `LastName=${lastName},`;
        else sql += `LastName='${lastName}',`;
    }
    let objWorkPhone =  scimgateway.getArrayObject(attrObj, 'phoneNumbers', 'work') || {};
    let phoneNumber = (objWorkPhone.operation && objWorkPhone.operation === 'delete') ? null : objWorkPhone.value;
    if (!phoneNumber && objWorkPhone.operation === 'modify') phoneNumber = null; // value not included if blank    
    if (phoneNumber !== undefined) {
        if (phoneNumber === null) sql += `MobilePhone=${phoneNumber},`;
        else sql += `MobilePhone='${phoneNumber}',`;
    }
    let objWorkEmail =  scimgateway.getArrayObject(attrObj, 'emails', 'work') || {};
    let emailAddress = (objWorkEmail.operation && objWorkEmail.operation === 'delete') ? null : objWorkEmail.value;
    if (!emailAddress && objWorkEmail.operation === 'modify') emailAddress = null; // value not included if blank
    if (emailAddress !== undefined) {
        if (emailAddress === null) sql += `Email=${emailAddress},`;
        else sql += `Email='${emailAddress}',`;
    }

    sql = sql.substr(0, sql.length - 1) // remove trailing ","
    let connection = new Connection(config.connection);

    connection.on('connect', function (err) {
        if (err) {
            console.log(err.message)
            var err = new Error(`Modify-Users connect: MSSQL client connect error: ${err.message}`);
            return callback(err);
        }
        let sqlQuery = `update [User] set ${sql} where UserID like '${id}'`
        let request = new Request(sqlQuery, function (err, rowCount, rows) {
            if (err) {
                connection.close();
                var err = new Error(`Modify-Users: MSSQL client request: ${sqlQuery} Error: ${err.message}`);
                return callback(err);
            }
            connection.close();
            callback(null);

        }); // request
        connection.execSql(request);

    }); // connection



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
// => plugin-mssql groups not implemented
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
// => plugin-mssql groups not implemented
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
// => plugin-mssql groups not implemented
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
//
// => plugin-mssql groups not implemented
//==========================================
scimgateway.on('modifyGroupMembers', function (baseEntity, id, members, callback) {
    var action = 'modifyGroupMembers';
    scimgateway.logger.debug(`${pluginName} handling event "${action}" id=${id} members=${JSON.stringify(members)}`);
    callback(null);
});

