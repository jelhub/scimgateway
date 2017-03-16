'use strict'

// Natural language-like assertions
const expect = require('chai').expect;
const scimgateway = require('../../lib/plugin-testmode.js');


const request = require('request');

const auth = "Basic " + new Buffer('gwadmin:password').toString("base64");
var options = {
    url: '',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': auth
    }
};


describe('plugin-testmode tests', () => {


    it('getUser (by id)', function (done) {
        options.url = 'http://localhost:8880/Users/bjensen';
        request.get(options, function (err, res, body) {
            let user = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(user).to.not.equal('undefined');
            expect(user.entitlements[0].value).to.equal('bjensen@example.com');
            expect(user.entitlements[0].type).to.equal('newentitlement');
            expect(user.name.formatted).to.equal('Ms. Barbara J Jensen III');
            expect(user.name.familyName).to.equal('Jensen');
            expect(user.name.givenName).to.equal('Barbara');
            expect(user.x509Certificates[0].value).to.equal('bjensen@example.com');
            expect(user.x509Certificates[0].type).to.equal('cert');
            expect(user.active).to.equal(true);
            expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8377');
            expect(user.phoneNumbers[0].type).to.equal('work');
            expect(user.roles[0].value).to.equal('bjensen@example.com');
            expect(user.roles[0].type).to.equal('newrole');
            expect(user.userName).to.equal('bjensen');
            expect(user.emails[0].value).to.equal('bjensen@example.com');
            expect(user.emails[0].type).to.equal('work');
            expect(user.ims[0].value).to.equal('bjensen@example.com');
            expect(user.ims[0].type).to.equal('aim');
            expect(user.photos[0].value).to.equal('bjensen@example.com');
            expect(user.photos[0].type).to.equal('photo');
            expect(user.id).to.equal('bjensen');
            expect(user.groups[0].display).to.equal('UserGroup-1');
            expect(user.groups[0].value).to.equal('UserGroup-1');
            expect(user.meta.created).to.equal('2016-01-11T08:42:21.596Z');
            expect(user.meta.lastModified).to.equal('2016-01-11T08:42:21.596Z');
            expect(user.meta.location).to.equal('http://localhost:8880/Users/bjensen');
            expect(user.meta.version).to.equal('"20160111084221.596Z"');
            done();
        });
    });


    it('getUser (by userName and attributes)', function (done) {
        options.url = 'http://localhost:8880/Users' +
            '?filter=userName eq "bjensen"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements,groups';
        request.get(options, function (err, res, body) {
            let user = JSON.parse(body);
            user = user.Resources[0];
            expect(res.statusCode).to.equal(200);
            expect(user).to.not.equal('undefined');
            expect(user.entitlements[0].value).to.equal('bjensen@example.com');
            expect(user.entitlements[0].type).to.equal('newentitlement');
            expect(user.name.formatted).to.equal('Ms. Barbara J Jensen III');
            expect(user.name.familyName).to.equal('Jensen');
            expect(user.name.givenName).to.equal('Barbara');
            expect(user.x509Certificates[0].value).to.equal('bjensen@example.com');
            expect(user.x509Certificates[0].type).to.equal('cert');
            expect(user.active).to.equal(true);
            expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8377');
            expect(user.phoneNumbers[0].type).to.equal('work');
            expect(user.roles[0].value).to.equal('bjensen@example.com');
            expect(user.roles[0].type).to.equal('newrole');
            expect(user.userName).to.equal('bjensen');
            expect(user.emails[0].value).to.equal('bjensen@example.com');
            expect(user.emails[0].type).to.equal('work');
            expect(user.ims[0].value).to.equal('bjensen@example.com');
            expect(user.ims[0].type).to.equal('aim');
            expect(user.photos[0].value).to.equal('bjensen@example.com');
            expect(user.photos[0].type).to.equal('photo');
            expect(user.id).to.equal('bjensen');
            expect(user.groups[0].display).to.equal('UserGroup-1');
            expect(user.groups[0].value).to.equal('UserGroup-1');
            expect(user.meta.created).to.equal('2016-01-11T08:42:21.596Z');
            expect(user.meta.lastModified).to.equal('2016-01-11T08:42:21.596Z');
            expect(user.meta.location).to.equal('http://localhost:8880/Users/bjensen');
            expect(user.meta.version).to.equal('"20160111084221.596Z"');
            done();
        });
    });


    it('exploreUsers', function (done) {
        options.url = 'http://localhost:8880/Users' +
            '?attributes=userName&startIndex=1&count=100';
        request.get(options, function (err, res, body) {
            let users = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(users).to.not.equal('undefined');
            expect(users.Resources[0].userName).to.equal('bjensen');
            expect(users.Resources[0].id).to.equal('bjensen');
            expect(users.Resources[1].userName).to.equal('jsmith');
            expect(users.Resources[1].id).to.equal('jsmith');
            done();
        });
    });


    it('exploreGroups', (done) => {
        options.url = 'http://localhost:8880/Groups' +
            '?attributes=displayName';
        request.get(options, function (err, res, body) {
            let groups = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(groups).to.not.equal('undefined');
            expect(groups.Resources[0].displayName).to.equal('Admins');
            expect(groups.Resources[0].id).to.equal('Admins');
            expect(groups.Resources[0].externalId).to.equal(undefined);
            expect(groups.Resources[1].displayName).to.equal('Employees');
            expect(groups.Resources[1].id).to.equal('Employees');
            expect(groups.Resources[1].externalId).to.equal(undefined);
            expect(groups.Resources[2].displayName).to.equal('UserGroup-1');
            expect(groups.Resources[2].id).to.equal('UserGroup-1');
            expect(groups.Resources[2].externalId).to.equal(undefined);
            expect(groups.Resources[3].displayName).to.equal('UserGroup-2');
            expect(groups.Resources[3].id).to.equal('UserGroup-2');
            expect(groups.Resources[3].externalId).to.equal(undefined);
            done();
        });
    });


    it('getGroup (by id)', function (done) {
        options.url = 'http://localhost:8880/Groups/Admins';
        request.get(options, function (err, res, body) {
            let group = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(group).to.not.equal('undefined');
            expect(group.displayName).to.equal('Admins');
            expect(group.id).to.equal('Admins');
            expect(group.members[0].value).to.equal('bjensen');
            expect(group.members[0].display).to.equal('bjensen');
            done();
        });
    });


    it('getGroup (by displayName and attributes)', function (done) {
        options.url = 'http://localhost:8880/Groups' +
            '?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName'
        request.get(options, function (err, res, body) {
            let groups = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(groups).to.not.equal('undefined');
            expect(groups.Resources[0].displayName).to.equal('Admins');
            expect(groups.Resources[0].id).to.equal('Admins');
            expect(groups.Resources[0].members[0].value).to.equal('bjensen');
            expect(groups.Resources[0].members[0].display).to.equal('bjensen');
            done();
        });
    });


    it('getGroupMembers', (done) => {
        options.url = 'http://localhost:8880/Groups' +
            '?filter=members.value eq "bjensen"&attributes=members.value,displayName'
        request.get(options, function (err, res, body) {
            let groupMembers = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(groupMembers).to.not.equal('undefined');
            expect(groupMembers.Resources[0].displayName).to.equal('Admins');
            expect(groupMembers.Resources[0].members[0].value).to.equal('bjensen');
            expect(groupMembers.Resources[0].totalResults).to.equal(groupMembers.Resources[0].members[0].length);
            done();
        });
    });


    it('getGroupUsers', (done) => {
        options.url = 'http://localhost:8880/Users' +
            '?filter=groups.value eq "UserGroup-1"&attributes=groups.value,userName'
        request.get(options, function (err, res, body) {
            let groupUsers = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(groupUsers).to.not.equal('undefined');
            expect(groupUsers.Resources[0].userName).to.equal('bjensen');
            done();
        });
    });


    it('convertedScim', (done) => {
        let user = {
            entitlements: [{
                value: 'jgilber@example.com',
                type: 'newentitlement'
            },
            {
                value: 'nobody@example.com',
                type: 'anotherentitlement'
            }],
            name: {
                formatted: 'Mr. Jeff Gilbert',
                familyName: 'Gilbert',
                givenName: 'Jeff'
            },
            x509Certificates: [{
                value: 'jgilber@example.com',
                type: 'cert'
            }],
            active: true,
            phoneNumbers: [{
                value: 'tel:555-555-8376',
                type: 'work'
            }],
            roles: [{
                value: 'jgilber@example.com',
                type: 'newrole'
            }],
            userName: 'jgilber',
            emails: [{
                "value": 'jgilber@example.com',
                "type": 'work'
            }],
            ims: [{
                value: 'jgilber@example.com',
                type: 'aim'
            }],
            photos: [{
                value: 'jgilber@example.com',
                type: 'photo'
            }],
            id: 'jgilber',
            groups: [{
                display: 'UserGroup-1',
                value: 'UserGroup-1'
            }],
            meta: { attributes: ['name.familyName', 'title'] }
        };

        user = scimgateway.convertedScim(user); // multivalue array to none-array based on type

        expect(user).to.not.equal('undefined');
        expect(user.entitlements.newentitlement.value).to.equal('jgilber@example.com');
        expect(user.entitlements.newentitlement.type).to.equal('newentitlement');
        expect(user.entitlements.anotherentitlement.value).to.equal('nobody@example.com');
        expect(user.entitlements.anotherentitlement.type).to.equal('anotherentitlement');
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
        expect(user.name.familyName).to.equal('');                      // cleared
        expect(user.name.givenName).to.equal('Jeff');
        expect(user.x509Certificates.cert.value).to.equal('jgilber@example.com');
        expect(user.x509Certificates.cert.type).to.equal('cert');
        expect(user.active).to.equal(true);
        expect(user.phoneNumbers.work.value).to.equal('tel:555-555-8376');
        expect(user.phoneNumbers.work.type).to.equal('work');
        expect(user.roles.newrole.value).to.equal('jgilber@example.com');
        expect(user.roles.newrole.type).to.equal('newrole');
        expect(user.userName).to.equal('jgilber');
        expect(user.emails.work.value).to.equal('jgilber@example.com');
        expect(user.emails.work.type).to.equal('work');
        expect(user.ims.aim.value).to.equal('jgilber@example.com');
        expect(user.ims.aim.type).to.equal('aim');
        expect(user.photos.photo.value).to.equal('jgilber@example.com');
        expect(user.photos.photo.type).to.equal('photo');
        expect(user.id).to.equal('jgilber');
        expect(user.groups[0].display).to.equal('UserGroup-1');         // groups not converted
        expect(user.groups[0].value).to.equal('UserGroup-1');
        expect(user.title).to.equal('');                                // cleared
        done();
    });


    it('createUser', (done) => {
        let newUser = {
            entitlements: [{
                value: 'jgilber@example.com',
                type: 'newentitlement'
            }],
            name: {
                formatted: 'Mr. Jeff Gilbert',
                familyName: 'Gilbert',
                givenName: 'Jeff'
            },
            x509Certificates: [{
                value: 'jgilber@example.com',
                type: 'cert'
            }],
            active: true,
            phoneNumbers: [{
                value: 'tel:555-555-8376',
                type: 'work'
            }],
            roles: [{
                value: 'jgilber@example.com',
                type: 'newrole'
            }],
            userName: 'jgilber',
            emails: [{
                "value": 'jgilber@example.com',
                "type": 'work'
            }],
            ims: [{
                value: 'jgilber@example.com',
                type: 'aim'
            }],
            photos: [{
                value: 'jgilber@example.com',
                type: 'photo'
            }],
            id: 'jgilber',
            groups: [{
                display: 'UserGroup-1',
                value: 'UserGroup-1'
            }]
        };

        options.url = 'http://localhost:8880/Users';
        options.body = JSON.stringify(newUser);
        request.post(options, function (err, res, body) {
            delete options.body;
            expect(err).to.equal(null);
            expect(res.statusCode).to.equal(201);
            done();
        });
    });


    it('getUser just created', (done) => {
        options.url = 'http://localhost:8880/Users/jgilber';
        request.get(options, function (err, res, body) {
            let user = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(user).to.not.equal('undefined');
            expect(user.entitlements[0].value).to.equal('jgilber@example.com');
            expect(user.entitlements[0].type).to.equal('newentitlement');
            expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
            expect(user.name.familyName).to.equal('Gilbert');
            expect(user.name.givenName).to.equal('Jeff');
            expect(user.x509Certificates[0].value).to.equal('jgilber@example.com');
            expect(user.x509Certificates[0].type).to.equal('cert');
            expect(user.active).to.equal(true);
            expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
            expect(user.phoneNumbers[0].type).to.equal('work');
            expect(user.roles[0].value).to.equal('jgilber@example.com');
            expect(user.roles[0].type).to.equal('newrole');
            expect(user.userName).to.equal('jgilber');
            expect(user.emails[0].value).to.equal('jgilber@example.com');
            expect(user.emails[0].type).to.equal('work');
            expect(user.ims[0].value).to.equal('jgilber@example.com');
            expect(user.ims[0].type).to.equal('aim');
            expect(user.photos[0].value).to.equal('jgilber@example.com');
            expect(user.photos[0].type).to.equal('photo');
            expect(user.id).to.equal('jgilber');
            expect(user.groups[0].display).to.equal('UserGroup-1');
            expect(user.groups[0].value).to.equal('UserGroup-1');
            done();
        });
    });


    it('modifyUser', (done) => {
        let user = {
            name: {
                givenName: 'Jeff-Modified'
            },
            active: false,
            phoneNumbers: [{
                value: 'tel:123',
                type: 'home'
            }],
            photos: [{
                operation: "delete",
                value: 'jgilber@example.com',
                type: 'photo'
            }],
            meta: { attributes: ['name.familyName'] }
        };

        options.url = 'http://localhost:8880/Users/jgilber';
        options.body = JSON.stringify(user);
        request.patch(options, function (err, res, body) {
            delete options.body;
            expect(err).to.equal(null);
            expect(res.statusCode).to.equal(200);
            done();
        });
    });


    it('getUser just modified', (done) => {
        options.url = 'http://localhost:8880/Users/jgilber';
        request.get(options, function (err, res, body) {
            let user = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(user).to.not.equal('undefined');
            expect(user.entitlements[0].value).to.equal('jgilber@example.com');
            expect(user.entitlements[0].type).to.equal('newentitlement');
            expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
            expect(user.name.familyName).to.equal(undefined);                       // cleared
            expect(user.name.givenName).to.equal('Jeff-Modified');                  // modified
            expect(user.x509Certificates[0].value).to.equal('jgilber@example.com');
            expect(user.x509Certificates[0].type).to.equal('cert');
            expect(user.active).to.equal(false);                                    // modified
            expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
            expect(user.phoneNumbers[0].type).to.equal('work');
            expect(user.phoneNumbers[1].value).to.equal('tel:123');                 // added
            expect(user.phoneNumbers[1].type).to.equal('home');                     // added
            expect(user.roles[0].value).to.equal('jgilber@example.com');
            expect(user.roles[0].type).to.equal('newrole');
            expect(user.userName).to.equal('jgilber');
            expect(user.emails[0].value).to.equal('jgilber@example.com');
            expect(user.emails[0].type).to.equal('work');
            expect(user.ims[0].value).to.equal('jgilber@example.com');
            expect(user.ims[0].type).to.equal('aim');
            expect(user.photos).to.equal(undefined);                                // deleted
            expect(user.id).to.equal('jgilber');
            expect(user.groups[0].display).to.equal('UserGroup-1');
            expect(user.groups[0].value).to.equal('UserGroup-1');
            done();
        });
    });


    it('deleteUser', (done) => {
        options.url = 'http://localhost:8880/Users/jgilber';
        request.delete(options, function (err, res, body) {
            expect(err).to.equal(null);
            expect(res.statusCode).to.equal(204);
            done();
        });
    });


    // using emit to avoid console error message regarding user not found
    it('getUser just deleted test', (done) => {
        scimgateway.emit('getUser', 'req.params.baseEntity', 'jgilber', null, function (err, data) {
            expect(err).to.not.equal(null);
            expect(err.message).to.equal('Could not find user with userName jgilber');
            expect(data).to.equal(undefined);
        });
        done();
    });


    it('createGroup', (done) => {
        let newGroup = {
            displayName: 'Undead',
            id: 'Undead',
            externalId: undefined,
            members: [{
                value: 'bjensen',
                display: 'bjensen'
            }]
        };

        options.url = 'http://localhost:8880/Groups';
        options.body = JSON.stringify(newGroup);
        request.post(options, function (err, res, body) {
            delete options.body;
            expect(err).to.equal(null);
            expect(res.statusCode).to.equal(201);
            done();
        });
    });


    it('getGroup just created', (done) => {
        options.url = 'http://localhost:8880/Groups/Undead';
        request.get(options, function (err, res, body) {
            let group = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(group).to.not.equal('undefined');
            expect(group.displayName).to.equal('Undead');
            expect(group.id).to.equal('Undead');
            expect(group.members[0].value).to.equal('bjensen');
            expect(group.members[0].display).to.equal('bjensen');
            done();
        });
    });


    it('modifyGroupMembers', (done) => {
        let members = { "members": [{ "value": "jsmith" }, { "operation": "delete", "value": "bjensen" }], "schemas": ["urn:scim:schemas:core:1.0"] }
        options.url = 'http://localhost:8880/Groups/Undead';
        options.body = JSON.stringify(members);
        request.patch(options, function (err, res, body) {
            delete options.body;
            expect(err).to.equal(null);
            expect(res.statusCode).to.equal(200);
            done();
        });
    });


    it('getGroup just modified members', (done) => {
        options.url = 'http://localhost:8880/Groups/Undead';
        request.get(options, function (err, res, body) {
            let group = JSON.parse(body);
            expect(res.statusCode).to.equal(200);
            expect(group).to.not.equal('undefined');
            expect(group.displayName).to.equal('Undead');
            expect(group.id).to.equal('Undead');
            expect(group.members.length).to.equal(1);
            expect(group.members[0].value).to.equal('jsmith');
            expect(group.members[0].display).to.equal('jsmith');
            done();
        });
    });


});
