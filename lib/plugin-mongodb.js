// =================================================================================
// File:    plugin-mongodb.js
//
// Authors: Filipe Ribeiro (KEEP SOLUTIONS)
//          Miguel Ferreira (KEEP SOLUTIONS)
//
// Purpose: SCIM endpoint locally at the ScimGateway
//          - Demonstrate userprovisioning towards a document-oriented database
//          - Using MongoDB document-oriented database with persistence
//          - Supporting explore, create, delete, modify and list users (including groups)
//
// Supported attributes:
//
// GlobalUser   Template            Scim        Endpoint
// ------------------------------------------------------
// All attributes are supported, note multivalue "type" must be unique
//
// =================================================================================

"use strict";

const MongoClient = require("mongodb").MongoClient;

// mandatory plugin initialization - start
const path = require("path");
let ScimGateway = null;
try {
  ScimGateway = require("./scimgateway");
} catch (err) {
  ScimGateway = require("scimgateway");
}
const scimgateway = new ScimGateway();
const pluginName = path.basename(__filename, ".js");
const configDir = path.join(__dirname, "..", "config");
//const configFile = path.join(`${configDir}`, `${pluginName}.json`);
const configFile = path.join(`${configDir}`, `${pluginName}.json`);
const validScimAttr = []; // empty array - all attrbutes are supported by endpoint
let config = require(configFile).endpoint;
config = scimgateway.processExtConfig(pluginName, config); // add any external config process.env and process.file
// mandatory plugin initialization - end

// let endpointPasswordExample = scimgateway.getPassword('endpoint.password', configFile); // example how to encrypt configfile having "endpoint.password"

var users;
var groups;
let db;

let dbname = config.connection.dbname ? config.connection.dbname : "scim";
const DB_CONNECTION = 'mongodb://' + config.connection.username + ':' + config.connection.password + '@' + config.connection.hostname + ':' + config.connection.port + '/' + dbname;

const client = new MongoClient(DB_CONNECTION, { useUnifiedTopology: true });

loadHandler();

async function loadHandler() {

  try {
    await client.connect();
    db = await client.db(dbname);
    await db.dropCollection("users");
    await db.dropCollection("groups");
    users = await db.collection('users');
    groups = await db.collection("groups");

    //TODO REMOVER FOREACH por FOR 
    //REMOVER CHAMADAS AO LOADHANDLER
    if ((await users.find().toArray()).length == 0) {
      scimgateway.testmodeusers.forEach(async record => {
        try {
          record = encodeDot(record);
          await users.insertOne(record)
        } catch (error) {
          throw new Error(`Failed to insert user`, error);
        }
      })
    }
    if ((await groups.find().toArray()).length == 0) {
      scimgateway.testmodegroups.forEach(async record => {
        try {
          record = encodeDot(record);
          await groups.insertOne(record)
        } catch (error) {
          throw new Error(`Failed to insert group`, error);
        }
      })
    }
  } catch (error) {
    throw new Error(`Failed to connecto do DB`, error);
  }
}

// =================================================
// exploreUsers
// =================================================
scimgateway.exploreUsers = async (
  baseEntity,
  attributes,
  startIndex = 1,
  count = 500
) => {
  const action = "exploreUsers";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`
  );
  const ret = {
    // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  };
  try {
    if (!users) { await loadHandler(); }
    const usersArr = await users.find({}, { projection: { _id: 0 } }).sort({ _id: 1 }).skip(startIndex - 1).limit(count).toArray();

    if (!startIndex && !count) {
      // client request without paging
      startIndex = 1;
      count = usersArr.length;
      if (count > 500) count = 500;
    }

    const arr = usersArr.map((obj) => {
      return decodeDot(obj);
    }); // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
    const usersDelta = arr.slice(startIndex - 1, startIndex - 1 + count);
    Array.prototype.push.apply(ret.Resources, usersDelta);
    ret.totalResults = usersDelta.length;
    return ret; // all explored users 
  } catch (error) {
    throw new Error(`Failed to get users`, error);
  }
};

// =================================================
// exploreGroups
// =================================================
scimgateway.exploreGroups = async (
  baseEntity,
  attributes,
  startIndex = 1,
  count = 500
) => {
  const action = "exploreGroups";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" attributes=${attributes} startIndex=${startIndex} count=${count}`
  );

  const ret = {
    // itemsPerPage will be set by scimgateway
    Resources: [],
    totalResults: null,
  };

  try {
    const groupsArr = await groups.find({}, { projection: { _id: 0 } }).sort({ _id: 1 }).skip(startIndex - 1).limit(count).toArray();

    if (!startIndex && !count) {
      // client request without paging
      startIndex = 1;
      count = groupsArr.length;
    }

    const arr = groupsArr.map((obj) => {
      return decodeDot(obj);
    }); // includes all groups attributes (also members)
    const groupsDelta = arr.slice(startIndex - 1, startIndex - 1 + count);
    Array.prototype.push.apply(ret.Resources, groupsDelta);
    ret.totalResults = groupsDelta.length;
    return ret; // all explored groups
  } catch (error) {
    throw new Error(`Failed to get groups`, error);
  }
};

// =================================================
// getUser
// =================================================
scimgateway.getUser = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'userName', identifier: 'bjensen'}
  // filter: userName and id must be supported
  // (they are most often considered as "the same" where identifier = UserID )
  // Note, the value of id attribute returned will be used by modifyUser and deleteUser
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // SCIM Gateway will automatically filter response according to the attributes list
  const action = "getUser";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`
  );

  const findObj = getMongoQuery(getObj);
  let projection = attributes ? getProjectionFromAttributes(attributes) : { _id: 0 };

  try {
    const res = await users.find(findObj, { projection: projection }).toArray();
    if (res.length !== 1) return null; // no user, or more than one user found
    res[0] = decodeDot(res[0]);
    return res[0]; // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
  } catch (error) {
    throw new Error(`Failed to get user`, error);
  }

};

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj) => {
  if (!users) { await loadHandler(); }
  const action = "createUser";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(
      userObj
    )}`
  );

  const notValid = scimgateway.notValidAttributes(userObj, validScimAttr); // We should check for unsupported endpoint attributes
  if (notValid) {
    const err = new Error(
      `unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    );
    throw err;
  }

  if (userObj.password) delete userObj.password; // exclude password db not ecrypted
  for (var key in userObj) {
    if (!Array.isArray(userObj[key]) && scimgateway.isMultiValueTypes(key)) {
      // true if attribute is "type converted object" => convert to standard array
      const arr = [];
      for (var el in userObj[key]) {
        userObj[key][el].type = el;
        if (el === "undefined") delete userObj[key][el].type; // type "undefined" reverted back to original blank
        arr.push(userObj[key][el]); // create
      }
      userObj[key] = arr;
    }
  }

  userObj = encodeDot(userObj);
  userObj.id = userObj.userName; // for loki-plugin (scim endpoint) id is mandatory and set to userName
  try {
    await users.insertOne(userObj);
  } catch (error) {
    throw new Error(`Failed to insert user`, error);
  }
  return null;
};

// =================================================
// deleteUser
// =================================================
scimgateway.deleteUser = async (baseEntity, id) => {
  const action = "deleteUser";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" id=${id}`
  );

  try {
    const res = await users.deleteOne({ id: id });
    return null;
  } catch (error) {
    throw new Error(`Failed to delete user with id=${id}`);
  }
};

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj) => {
  const action = "modifyUser";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(
      attrObj
    )}`
  );

  const notValid = scimgateway.notValidAttributes(attrObj, validScimAttr); // We should check for unsupported endpoint attributes
  if (notValid) {
    const err = new Error(
      `unsupported scim attributes: ${notValid} ` +
      `(supporting only these attributes: ${validScimAttr.toString()})`
    );
    throw err;
  }
  if (attrObj.password) delete attrObj.password; // exclude password db not ecrypted

  let res;

  try {
    res = await users.find({ id }, { projection: { _id: 0 } }).toArray();
    if (res.length !== 1) return null;
  } catch (error) {
    throw new Error(`Could not find user with id=${id}`);
  }

  let userObj = decodeDot(res[0]);

  for (var key in attrObj) {
    if (Array.isArray(attrObj[key])) {
      // standard, not using type (e.g groups)
      attrObj[key].forEach((el) => {
        if (el.operation === "delete") {
          userObj[key] = userObj[key].filter((e) => e.value !== el.value);
          if (userObj[key].length < 1) delete userObj[key];
        } else {
          // add
          if (!userObj[key]) userObj[key] = [];
          let exists;
          if (el.value)
            exists = userObj[key].find((e) => e.value && e.value === el.value);
          if (!exists) userObj[key].push(el);
        }
      });
    } else if (scimgateway.isMultiValueTypes(key)) {
      // "type converted object" logic and original blank type having type "undefined"
      if (!attrObj[key]) delete userObj[key]; // blank or null
      for (var el in attrObj[key]) {
        attrObj[key][el].type = el;
        if (
          attrObj[key][el].operation &&
          attrObj[key][el].operation === "delete"
        ) {
          // delete multivalue
          let type = el;
          if (type === "undefined") type = undefined;
          userObj[key] = userObj[key].filter((e) => e.type !== type);
          if (userObj[key].length < 1) delete userObj[key];
        } else {
          // modify/create multivalue
          if (!userObj[key]) userObj[key] = [];
          var found = userObj[key].find((e, i) => {
            if (e.type === el || (!e.type && el === "undefined")) {
              for (const k in attrObj[key][el]) {
                userObj[key][i][k] = attrObj[key][el][k];
                if (k === "type" && attrObj[key][el][k] === "undefined")
                  delete userObj[key][i][k]; // don't store with type "undefined"
              }
              return true;
            } else return false;
          });
          if (attrObj[key][el].type && attrObj[key][el].type === "undefined")
            delete attrObj[key][el].type; // don't store with type "undefined"
          if (!found) userObj[key].push(attrObj[key][el]); // create
        }
      }
    } else {
      // None multi value attribute
      if (typeof attrObj[key] !== "object" || attrObj[key] === null) {
        if (attrObj[key] === "" || attrObj[key] === null) delete userObj[key];
        else userObj[key] = attrObj[key];
      } else {
        // name.familyName=Bianchi
        if (!userObj[key]) userObj[key] = {}; // e.g name object does not exist
        for (var sub in attrObj[key]) {
          // attributes to be cleard located in meta.attributes eg: {"meta":{"attributes":["name.familyName","profileUrl","title"]}
          if (sub === "attributes" && Array.isArray(attrObj[key][sub])) {
            attrObj[key][sub].forEach((element) => {
              var arrSub = element.split(".");
              if (arrSub.length === 2) userObj[arrSub[0]][arrSub[1]] = "";
              // e.g. name.familyName
              else userObj[element] = "";
            });
          } else {
            if (
              Object.prototype.hasOwnProperty.call(
                attrObj[key][sub],
                "value"
              ) &&
              attrObj[key][sub].value === ""
            )
              delete userObj[key][sub];
            // object having blank value attribute e.g. {"manager": {"value": "",...}}
            else if (attrObj[key][sub] === "") delete userObj[key][sub];
            else {
              if (!userObj[key]) userObj[key] = {}; // may have been deleted by length check below
              userObj[key][sub] = attrObj[key][sub];
            }
            if (Object.keys(userObj[key]).length < 1) delete userObj[key];
          }
        }
      }
    }
  }

  userObj = encodeDot(userObj);

  try {
    await users.replaceOne({ id: id }, userObj);
    return null
  } catch (error) {
    throw new Error(`Failed to update user with id=${id}`, error);
  }
};

// =================================================
// getGroup
// =================================================
scimgateway.getGroup = async (baseEntity, getObj, attributes) => {
  // getObj = { filter: <filterAttribute>, identifier: <identifier> }
  // e.g: getObj = { filter: 'displayName', identifier: 'GroupA' }
  // filter: displayName and id must be supported
  // (they are most often considered as "the same" where identifier = GroupName)
  // Note, the value of id attribute returned will be used by deleteGroup, getGroupMembers and modifyGroup
  // attributes: if not blank, attributes listed should be returned
  // Should normally return all supported group attributes having id, displayName and members as mandatory
  // members may be skipped if attributes is not blank and do not contain members or members.value
  const action = "getGroup";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" ${getObj.filter}=${getObj.identifier} attributes=${attributes}`
  );

  const findObj = getMongoQuery(getObj);
  let projection = attributes ? getProjectionFromAttributes(attributes) : { _id: 0 };

  try {
    const res = await groups.find(findObj, { projection: projection }).toArray();
    if (res.length !== 1) return null; // no user, or more than one user found
    res[0] = decodeDot(res[0]);
    return res[0]; // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
  } catch (error) {
    throw new Error(`Failed to get group`, error);
  }

};

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  // return all groups the user is member of having attributes included e.g: members.value,id,displayName
  // method used when "users member of group", if used - getUser must treat user attribute groups as virtual readOnly attribute
  // "users member of group" is SCIM default and this method should normally have some logic
  const action = "getGroupMembers";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`
  );

  let arrRet = [];
  let projection = attributes ? getProjectionFromAttributes(attributes) : { _id: 0 };
  let data = await groups.find({ members: { value: id, display: id } }, { projection: projection }).toArray();

  data.forEach((el) => {
    if (el.members) {
      const userFound = el.members.find((element) => element.value === id);
      if (userFound) {
        el = decodeDot(el);
        let arrAttr = [];
        if (attributes) arrAttr = attributes.split(",");
        const userGroup = {};
        arrAttr.forEach((attr) => {
          if (el[attr]) userGroup[attr] = el[attr]; // id, displayName, members.value
        });
        userGroup.members = [{ value: id }]; // only includes current user (not all members)
        arrRet.push(userGroup); // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
      }
    }
  });
  return arrRet;
};

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, id, attributes) => {
  // return array of all users that is member of this group id having attributes included e.g: groups.value,userName
  // method used when "group member of users", if used - getGroup must treat group attribute members as virtual readOnly attribute
  const action = "getGroupUsers";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" id=${id} attributes=${attributes}`
  );

  let arrRet = [];
  let projection = attributes ? getProjectionFromAttributes(attributes) : { _id: 0 };
  let data = await users.find({ groups: { value: id } }, { projection: projection }).toArray();

  data.forEach((user) => {
    if (user.groups) {
      user = decodeDot(user);
      user.groups.forEach((group) => {
        if (group.value === id) {
          arrRet.push(
            // {userName: "bjensen", groups: [{value: <group id>}]} - value only includes current group id
            {
              userName: user.userName,
              groups: [{ value: id }],
            }
          );
        }
      });
    }
  });
  return arrRet;
};

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj) => {
  const action = "createGroup";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(
      groupObj
    )}`
  );

  groupObj.id = groupObj.displayName; // for loki-plugin (scim endpoint) id is mandatory and set to displayName
  groupObj = encodeDot(groupObj);

  try {
    await groups.insertOne(groupObj);
    return null;
  } catch (error) {
    throw new Error(`Failed to insert group`, error);
  }
};

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id) => {
  const action = "deleteGroup";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" id=${id}`
  );


  try {
    const res = await groups.deleteOne({ id: id });
    return null;
  } catch (error) {
    throw new Error(`Failed to delete group with id=${id}`);
  }
};

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj) => {
  const action = "modifyGroup";
  scimgateway.logger.debug(
    `${pluginName}[${baseEntity}] handling "${action}" id=${id} attrObj=${JSON.stringify(
      attrObj
    )}`
  );

  if (!attrObj.members) {
    throw new Error(
      `plugin handling "${action}" only supports modification of members`
    );
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(
      `plugin handling "${action}" error: ${JSON.stringify(
        attrObj
      )} - correct syntax is { "members": [...] }`
    );
  }
  let res;

  try {
    res = await groups.find({ id: id }, { projection: { _id: 0 } }).toArray();
    if (res.length !== 1) return null;
  } catch (error) {
    throw new Error(`Failed to find group with id=${id}`);
  }

  let groupObj = decodeDot(res[0]);

  if (!groupObj.members) groupObj.members = [];
  const usersNotExist = [];

  for (let el of attrObj.members) {
    if (el.operation && el.operation === "delete") {
      // delete member from group
      if (!el.value) groupObj.members = [];
      // members=[{"operation":"delete"}] => no value, delete all members
      else
        groupObj.members = groupObj.members.filter(
          (element) => element.value !== el.value
        );
    } else {
      // Add member to group
      if (el.value) {
        // check if user exist
        let usr;
        try {
          usr = await users.find({ id: el.value }, { projection: { _id: 0 } }).toArray();
        } catch (error) {
          throw new Error(`Could not find user with id=${id}`);
        }
        if (!usr) {
          usersNotExist.push(el.value);
          return;
        }
      }
      var newMember = {
        display: el.value,
        value: el.value,
      };

      let exists;
      if (el.value)
        exists = groupObj.members.find((e) => el.value && e.value === el.value);
      if (!exists) groupObj.members.push(newMember);
    }
  }

  groupObj = encodeDot(groupObj);
  try {
    await groups.replaceOne({ id: groupObj.id }, groupObj);
  } catch (error) {
    throw new Error(`Failed to update group with id=${groupObj.id}`);
  }

  if (usersNotExist.length > 0)
    throw new Error(
      `can't use ${action} including none existing user(s): ${usersNotExist.toString()}`
    );
  return null;
};

// =================================================
// helpers
// =================================================
const decodeDot = (obj) => { // replace dot with unicode
  const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify source
  if (retObj.meta) {
    if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString()
    delete retObj.meta.lastModified // test users loaded
    if (retObj.meta.updated) {
      retObj.meta.lastModified = new Date(retObj.meta.updated).toISOString()
      delete retObj.meta.updated
    }
    if (retObj.meta.revision !== undefined) {
      retObj.meta.version = retObj.meta.revision
      delete retObj.meta.revision
    }
  }
  Object.keys(retObj).forEach(function (key) {
    if (key.includes("·")) {
      retObj[key.replace(/\·/g, ".")] = retObj[key];
      delete retObj[key];
    }
  });
  return retObj
}

const encodeDot = (obj) => { // replace dot with unicode
  const retObj = JSON.parse(JSON.stringify(obj)) // new object - don't modify source
  if (retObj._id) delete retObj._id;
  if (retObj.meta) {
    if (retObj.meta.created) retObj.meta.created = new Date(retObj.meta.created).toISOString()
    delete retObj.meta.lastModified // test users loaded
    if (retObj.meta.updated) {
      retObj.meta.lastModified = new Date(retObj.meta.updated).toISOString()
      delete retObj.meta.updated
    }
    if (retObj.meta.revision !== undefined) {
      retObj.meta.version = retObj.meta.revision
      delete retObj.meta.revision
    }
  }
  Object.keys(retObj).forEach(function (key) {
    if (key.includes(".")) {
      retObj[key.replace(/\./g, '·')] = retObj[key];
      delete retObj[key];
    }
  });
  return retObj
}

function getProjectionFromAttributes(attributes) {
  let arrAttr = attributes.split(",");
  const projection = {};
  arrAttr.forEach((attr) => {
    projection[attr] = attr;
  });
}

function getMongoQuery(getObj) {
  let findObj = {};
  if (getObj.operator === 'eq') {
    findObj[getObj.filter] = getObj.identifier;
  } else if (getObj.operator === 'gte') {
    findObj[getObj.filter] = { '$gte': new Date(getObj.identifier).toISOString() };
  } else {
    findObj[getObj.filter] = getObj.identifier;
  }
  console.log(findObj);
  return findObj;
}
//
// Cleanup on exit
//
process.on("SIGTERM", () => {
  // kill
  db.close();
});
process.on("SIGINT", () => {
  // Ctrl+C
  db.close();
});
