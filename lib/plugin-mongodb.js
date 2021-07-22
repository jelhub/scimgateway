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

/** Exemplo de integração com o Mongo
 * 
const MONGODB_HOST = "oraculo_db";
const MONGODB_PORT = 27017;
const DB_NAME = "oraculo";
const DB_CONNECTION = `mongodb://${MONGODB_HOST}:${MONGODB_PORT}`;
const DB_RESULTS_COLLECTION = "strategic_indicators";

// INSERT
  console.log("Writing to database", data);
  let col = db.collection(DB_RESULTS_COLLECTION);
  await col.insertOne(data);

  // QUERY
  client = new MongoClient(DB_CONNECTION, { useUnifiedTopology: true });
  await client.connect();
  db = client.db(DB_NAME);
  let col = db.collection(collection);
  await col.aggregate(aggregation)
*/

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
    users = await db.collection('users');

    /*  if (users === null) {
        // if database do not exist it will be empty so intitialize here
        users = db.addCollection("users", {
          unique: ["id", "userName"],
        });
      } */

    groups = db.collection("groups");
    // if (groups === null) {
    //   groups = db.addCollection("groups", {
    //     unique: ["displayName"],
    //   });
    // }

    if ((await users.find().toArray()).length == 0) {
      scimgateway.testmodeusers.forEach(async record => {
        if (record.meta) delete record.meta
        try {
          await users.insertOne(record)
        } catch (error) {
          console.log(error);
        }
      })
      scimgateway.testmodegroups.forEach(async record => {
        try {
          await groups.insertOne(record)

        } catch (error) {
          console.log(error);
        }
      })
    }
  } catch (err) {
    console.log(err);
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
    const usersArr = await users.find({}).sort({ _id: 1 }).skip(startIndex - 1).limit(count).toArray();

    if (!startIndex && !count) {
      // client request without paging
      startIndex = 1;
      count = usersArr.length;
      if (count > 500) count = 500;
    }

    // const arr = usersArr.map((obj) => {
    //   //return stripLoki(obj);
    // }); // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
    const usersDelta = usersArr.slice(startIndex - 1, startIndex - 1 + count);
    Array.prototype.push.apply(ret.Resources, usersDelta);
    ret.totalResults = usersDelta.length;
    return ret; // all explored users 
  } catch (error) {
    console.error(error);
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
  const groupsArr = await groups.find({}).sort({ _id: 1 }).skip(startIndex - 1).limit(count).toArray();

  if (!startIndex && !count) {
    // client request without paging
    startIndex = 1;
    count = groupsArr.length;
  }

  const arr = groupsArr.map((obj) => {
    //return stripLoki(obj);
  }); // includes all groups attributes (also members)
  const groupsDelta = groupsArr.slice(startIndex - 1, startIndex - 1 + count);
  Array.prototype.push.apply(ret.Resources, groupsDelta);
  ret.totalResults = groupsDelta.length;
  return ret; // all explored groups
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

  const findObj = {};
  findObj[getObj.filter] = getObj.identifier; // { userName: 'bjensen } / { externalId: 'bjensen } / { id: 'bjensen } / { 'emails.value': 'jsmith@example.com'} / { 'phoneNumbers.value': '555-555-5555'}

  const res = await users.find(findObj).toArray();
  if (res.length !== 1) return null; // no user, or more than one user found
  return res[0]; // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
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
    if (key.includes(".")) {
      userObj[key.replace(".", "\\u002e")] = userObj[key];
      delete userObj[key];
    }
  }

  userObj.id = userObj.userName; // for loki-plugin (scim endpoint) id is mandatory and set to userName
  try {
    //users.insert(userObj);
    await users.insertOne(userObj);
  } catch (err) {
    console.log(err);
    throw err;
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
    res = await users.find({ id: id }).toArray();
    if (res.length !== 1) return null;
  } catch (error) {
    throw new Error(`Could not find user with id=${id}`);
  }

  const userObj = res[0];

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
  try {
    await users.update({ id: id }, userObj);
    return null
  } catch (error) {
    console.error(error);
  }
  return null;
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

  const findObj = {};
  findObj[getObj.filter] = getObj.identifier; // { displayName: 'GroupA' }

  const res = await groups.find(findObj).toArray();
  if (res.length !== 1) return null; // no user, or more than one user found
  return res[0]; // includes all user attributes but groups - user attribute groups automatically handled by scimgateway
};

// =================================================
// getGroupMembers
// =================================================
scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
  // return all groups the user is member of having attributes included e.g: members.value,id,displayName
  // method used when "users member of group", if used - getUser must treat user attribute groups as virtual readOnly attribute
  // "users member of group" is SCIM default and this method should normally have some logic
  const action = 'getGroupMembers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet // groups not implemented
}

// =================================================
// getGroupUsers
// =================================================
scimgateway.getGroupUsers = async (baseEntity, id, attributes) => {
  // return array of all users that is member of this group id having attributes included e.g: groups.value,userName
  // method used when "group member of users", if used - getGroup must treat group attribute members as virtual readOnly attribute
  const action = 'getGroupUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id} attributes=${attributes}`)
  const arrRet = []
  return arrRet
}

// // =================================================
// // getGroupMembers
// // =================================================
// scimgateway.getGroupMembers = async (baseEntity, id, attributes) => {
//   // return all groups the user is member of having attributes included e.g: members.value,id,displayName
//   // method used when "users member of group", if used - getUser must treat user attribute groups as virtual readOnly attribute
//   // "users member of group" is SCIM default and this method should normally have some logic
//   const action = "getGroupMembers";
//   scimgateway.logger.debug(
//     `${pluginName}[${baseEntity}] handling "${action}" user id=${id} attributes=${attributes}`
//   );

//   const arrRet = [];
//   //TODO: Refactor use MongoDB query instead of loading all groups
//   let data = await groups.find().toArray();
//   data.forEach((el) => {
//     if (el.members) {
//       const userFound = el.members.find((element) => element.value === id);
//       if (userFound) {
//         let arrAttr = [];
//         if (attributes) arrAttr = attributes.split(",");
//         const userGroup = {};
//         arrAttr.forEach((attr) => {
//           if (el[attr]) userGroup[attr] = el[attr]; // id, displayName, members.value
//         });
//         userGroup.members = [{ value: id }]; // only includes current user (not all members)
//         arrRet.push(userGroup); // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
//       }
//     }
//   });
//   return arrRet;
// };

// // =================================================
// // getGroupUsers
// // =================================================
// scimgateway.getGroupUsers = async (baseEntity, id, attributes) => {
//   // return array of all users that is member of this group id having attributes included e.g: groups.value,userName
//   // method used when "group member of users", if used - getGroup must treat group attribute members as virtual readOnly attribute
//   const action = "getGroupUsers";
//   scimgateway.logger.debug(
//     `${pluginName}[${baseEntity}] handling "${action}" id=${id} attributes=${attributes}`
//   );

//   const arrRet = [];
//   users.data.forEach((user) => {
//     if (user.groups) {
//       user.groups.forEach((group) => {
//         if (group.value === id) {
//           arrRet.push(
//             // {userName: "bjensen", groups: [{value: <group id>}]} - value only includes current group id
//             {
//               userName: user.userName,
//               groups: [{ value: id }],
//             }
//           );
//         }
//       });
//     }
//   });
//   return arrRet;
// };

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
  try {
    //users.insert(userObj);
    await groups.update({ id: groupObj.id }, groupObj, { upsert: true });
    return null;
  } catch (err) {
    console.log(err);
    throw err;
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
    res = await groups.find({ id: id }).toArray();
    if (res.length !== 1) return null;
  } catch (error) {
    throw new Error(`Failed to find group with id=${id}`);
  }

  const groupObj = res[0];

  if (!groupObj.members) groupObj.members = [];
  const usersNotExist = [];

  await attrObj.members.forEach(async (el) => {
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
        const usrObj = { filter: "id", identifier: el.value };
        const usr = await scimgateway.getUser(baseEntity, usrObj, "id");
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
  });

  await groups.update({ id: groupObj.id }, groupObj);

  if (usersNotExist.length > 0)
    throw new Error(
      `can't use ${action} including none existing user(s): ${usersNotExist.toString()}`
    );
  return null;
};

// =================================================
// helpers
// =================================================


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
