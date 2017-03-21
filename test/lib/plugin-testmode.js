'use strict'

// Natural language-like assertions
const expect = require('chai').expect;
const scimgateway = require('../../lib/plugin-testmode.js');
const server_8880 = require('supertest').agent('http://localhost:8880'); // module request is an alternative

const auth = "Basic " + new Buffer('gwadmin:password').toString("base64");
var options = {
     headers: {
        'Content-Type': 'application/json',
        'Authorization': auth
    }
};


describe('plugin-testmode tests', () => {


    it('exploreUsers test', function (done) {
        server_8880.get('/Users' +
            '?attributes=userName&startIndex=1&count=100')
            .set(options.headers)
            .end(function (err, res) {
                let users = res.body;
                expect(res.statusCode).to.equal(200);
                expect(users.totalResults).to.equal(2);
                expect(users.itemsPerPage).to.equal(2);
                expect(users.startIndex).to.equal(1);
                expect(users).to.not.equal('undefined');
                expect(users.Resources[0].userName).to.equal('bjensen');
                expect(users.Resources[0].id).to.equal('bjensen');
                expect(users.Resources[1].userName).to.equal('jsmith');
                expect(users.Resources[1].id).to.equal('jsmith');
                done();
            });
    });


    it('exploreGroups test', (done) => {
        server_8880.get('/Groups' +
            '?attributes=displayName&startIndex=1&count=100')
            .set(options.headers)
            .end(function (err, res) {
                let groups = res.body;
                expect(res.statusCode).to.equal(200);
                expect(groups.totalResults).to.equal(4);
                expect(groups.itemsPerPage).to.equal(4);
                expect(groups.startIndex).to.equal(1);              
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


    it('getUser test (1)', function (done) {
        server_8880.get('/Users/bjensen')
            .set(options.headers)
            .end(function (err, res) {
                let user = res.body;
                expect(res.statusCode).to.equal(200);
                expect(user.meta.location).to.not.equal(undefined); 
                expect(user).to.not.equal(undefined);
                expect(user.schemas).to.not.equal(undefined); 
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


    it('getUser test (2)', function (done) {
        server_8880.get('/Users' +
            '?filter=userName eq "bjensen"&attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements,groups')
            .set(options.headers)
            .end(function (err, res) {
                let user = res.body;
                user = user.Resources[0];
                expect(res.statusCode).to.equal(200);
                expect(user).to.not.equal(undefined);
                expect(user.id).to.equal('bjensen');
                expect(user.userName).to.equal('bjensen');
                expect(user.active).to.equal(true);
                expect(user.name.givenName).to.equal('Barbara');
                expect(user.name.familyName).to.equal('Jensen');
                expect(user.name.formatted).to.equal('Ms. Barbara J Jensen III');
                expect(user.entitlements[0].value).to.equal('bjensen@example.com');
                expect(user.entitlements[0].type).to.equal('newentitlement');
                expect(user.x509Certificates[0].value).to.equal('bjensen@example.com');
                expect(user.x509Certificates[0].type).to.equal('cert');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8377');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.roles[0].value).to.equal('bjensen@example.com');
                expect(user.roles[0].type).to.equal('newrole');
                expect(user.emails[0].value).to.equal('bjensen@example.com');
                expect(user.emails[0].type).to.equal('work');
                expect(user.ims[0].value).to.equal('bjensen@example.com');
                expect(user.ims[0].type).to.equal('aim');
                expect(user.photos[0].value).to.equal('bjensen@example.com');
                expect(user.photos[0].type).to.equal('photo');
                expect(user.groups[0].display).to.equal('UserGroup-1');
                expect(user.groups[0].value).to.equal('UserGroup-1');
                expect(user.meta.created).to.equal('2016-01-11T08:42:21.596Z');
                expect(user.meta.lastModified).to.equal('2016-01-11T08:42:21.596Z');
                expect(user.meta.location).to.equal('http://localhost:8880/Users/bjensen');
                expect(user.meta.version).to.equal('"20160111084221.596Z"');
                expect(res.body.schemas).to.not.equal(undefined);
                done();
            });
    });




    it('getGroup test (1)', function (done) {

        server_8880.get('/Groups/Admins')
            .set(options.headers)
            .end(function (err, res) {
                let group = res.body;
                expect(res.statusCode).to.equal(200);
                expect(group).to.not.equal(undefined);
                expect(group.schemas).to.not.equal(undefined);
                expect(group.meta.location).to.not.equal(undefined); 
                expect(group.displayName).to.equal('Admins');
                expect(group.id).to.equal('Admins');
                expect(group.members[0].value).to.equal('bjensen');
                expect(group.members[0].display).to.equal('bjensen');
                done();
            });
    });


    it('getGroup test (2)', function (done) {
        server_8880.get('/Groups' +
            '?filter=displayName eq "Admins"&attributes=externalId,id,members.value,displayName')
            .set(options.headers)
            .end(function (err, res) {
                let groups = res.body;
                expect(res.statusCode).to.equal(200);
                expect(groups).to.not.equal(undefined);
                expect(groups.schemas).to.not.equal(undefined); 
                expect(groups.Resources[0].displayName).to.equal('Admins');
                expect(groups.Resources[0].id).to.equal('Admins');
                expect(groups.Resources[0].members[0].value).to.equal('bjensen');
                expect(groups.Resources[0].members[0].display).to.equal('bjensen');
                done();
            });
    });


    it('getGroupMembers test', (done) => {
        server_8880.get('/Groups' +
            '?filter=members.value eq "bjensen"&attributes=members.value,displayName')
            .set(options.headers)
            .end(function (err, res) {
                let groupMembers = res.body;
                expect(res.statusCode).to.equal(200);
                expect(groupMembers).to.not.equal('undefined');
                expect(groupMembers.Resources[0].displayName).to.equal('Admins');
                expect(groupMembers.Resources[0].members[0].value).to.equal('bjensen');
                expect(groupMembers.Resources[0].totalResults).to.equal(groupMembers.Resources[0].members[0].length);
                done();
            });
    });


    it('getGroupUsers test', (done) => {
        server_8880.get('/Users' +
            '?filter=groups.value eq "UserGroup-1"&attributes=groups.value,userName')
            .set(options.headers)
            .end(function (err, res) {
                let groupUsers = res.body;
                expect(res.statusCode).to.equal(200);
                expect(groupUsers).to.not.equal('undefined');
                expect(groupUsers.Resources[0].userName).to.equal('bjensen');
                done();
            });
    });


    it('convertedScim test', (done) => {
        let user = {
            id: 'jgilber',
            userName: 'jgilber',
            active: true,
            name: {
                formatted: 'Mr. Jeff Gilbert',
                familyName: 'Gilbert',
                givenName: 'Jeff'
            },
            entitlements: [{
                value: 'jgilber@example.com',
                type: 'newentitlement'
            },
            {
                value: 'nobody@example.com',
                type: 'anotherentitlement'
            }],
            x509Certificates: [{
                value: 'jgilber@example.com',
                type: 'cert'
            }],
            phoneNumbers: [{
                value: 'tel:555-555-8376',
                type: 'work'
            }],
            roles: [{
                value: 'jgilber@example.com',
                type: 'newrole'
            }],
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
            groups: [{
                display: 'UserGroup-1',
                value: 'UserGroup-1'
            }],
            meta: { attributes: ['name.familyName', 'title'] }
        };

        user = scimgateway.convertedScim(user); // multivalue array to none-array based on type

        expect(user).to.not.equal('undefined');
        expect(user.id).to.equal('jgilber');
        expect(user.userName).to.equal('jgilber');
        expect(user.active).to.equal(true);
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
        expect(user.name.familyName).to.equal('');                      // cleared
        expect(user.name.givenName).to.equal('Jeff');
        expect(user.title).to.equal('');                                // cleared
        expect(user.entitlements.newentitlement.value).to.equal('jgilber@example.com');
        expect(user.entitlements.newentitlement.type).to.equal('newentitlement');
        expect(user.entitlements.anotherentitlement.value).to.equal('nobody@example.com');
        expect(user.entitlements.anotherentitlement.type).to.equal('anotherentitlement');
        expect(user.x509Certificates.cert.value).to.equal('jgilber@example.com');
        expect(user.x509Certificates.cert.type).to.equal('cert');
        expect(user.phoneNumbers.work.value).to.equal('tel:555-555-8376');
        expect(user.phoneNumbers.work.type).to.equal('work');
        expect(user.roles.newrole.value).to.equal('jgilber@example.com');
        expect(user.roles.newrole.type).to.equal('newrole');
        expect(user.emails.work.value).to.equal('jgilber@example.com');
        expect(user.emails.work.type).to.equal('work');
        expect(user.ims.aim.value).to.equal('jgilber@example.com');
        expect(user.ims.aim.type).to.equal('aim');
        expect(user.photos.photo.value).to.equal('jgilber@example.com');
        expect(user.photos.photo.type).to.equal('photo');
        expect(user.groups[0].display).to.equal('UserGroup-1');         // groups not converted
        expect(user.groups[0].value).to.equal('UserGroup-1');
        done();
    });


    it('createUser test', (done) => {
        let newUser = {
            userName: 'jgilber',
            active: true,
            name: {
                formatted: 'Mr. Jeff Gilbert',
                familyName: 'Gilbert',
                givenName: 'Jeff'
            },
            entitlements: [{
                value: 'jgilber@example.com',
                type: 'newentitlement'
            }],
            x509Certificates: [{
                value: 'jgilber@example.com',
                type: 'cert'
            }],
            phoneNumbers: [{
                value: 'tel:555-555-8376',
                type: 'work'
            }],
            roles: [{
                value: 'jgilber@example.com',
                type: 'newrole'
            }],
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
            groups: [{
                display: 'UserGroup-1',
                value: 'UserGroup-1'
            }]
        };

        server_8880.post('/Users')
            .set(options.headers)
            .send(newUser)
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(201);
                expect(res.body.meta.location).to.equal('http://localhost:8880/Users/jgilber'); 
                done();
            });
    });


    it('getUser just created test', (done) => {
        server_8880.get('/Users/jgilber')
            .set(options.headers)
            .end(function (err, res) {
                let user = res.body;
                expect(res.statusCode).to.equal(200);
                expect(user).to.not.equal('undefined');
                expect(user.id).to.equal('jgilber');
                expect(user.userName).to.equal('jgilber');
                expect(user.active).to.equal(true);
                expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
                expect(user.name.familyName).to.equal('Gilbert');
                expect(user.name.givenName).to.equal('Jeff');
                expect(user.entitlements[0].value).to.equal('jgilber@example.com');
                expect(user.entitlements[0].type).to.equal('newentitlement');
                expect(user.x509Certificates[0].value).to.equal('jgilber@example.com');
                expect(user.x509Certificates[0].type).to.equal('cert');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.roles[0].value).to.equal('jgilber@example.com');
                expect(user.roles[0].type).to.equal('newrole');
                expect(user.emails[0].value).to.equal('jgilber@example.com');
                expect(user.emails[0].type).to.equal('work');
                expect(user.ims[0].value).to.equal('jgilber@example.com');
                expect(user.ims[0].type).to.equal('aim');
                expect(user.photos[0].value).to.equal('jgilber@example.com');
                expect(user.photos[0].type).to.equal('photo');
                expect(user.groups[0].display).to.equal('UserGroup-1');
                expect(user.groups[0].value).to.equal('UserGroup-1');
                done();
            });
    });


    it('modifyUser test', (done) => {
        var user = {
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

        server_8880.patch('/Users/jgilber')
            .set(options.headers)
            .send(user)
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(200);
                done();
            });
    });


    it('getUser just modified test', (done) => {
        server_8880.get('/Users/jgilber')
            .set(options.headers)
            .end(function (err, res) {
                let user = res.body;
                expect(res.statusCode).to.equal(200);
                expect(user).to.not.equal('undefined');
                expect(user.id).to.equal('jgilber');
                expect(user.userName).to.equal('jgilber');
                expect(user.active).to.equal(false);                                    // modified
                expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
                expect(user.name.familyName).to.equal(undefined);                       // cleared
                expect(user.name.givenName).to.equal('Jeff-Modified');                  // modified
                expect(user.entitlements[0].value).to.equal('jgilber@example.com');
                expect(user.entitlements[0].type).to.equal('newentitlement');
                expect(user.x509Certificates[0].value).to.equal('jgilber@example.com');
                expect(user.x509Certificates[0].type).to.equal('cert');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.phoneNumbers[1].value).to.equal('tel:123');                 // added
                expect(user.phoneNumbers[1].type).to.equal('home');                     // added
                expect(user.roles[0].value).to.equal('jgilber@example.com');
                expect(user.roles[0].type).to.equal('newrole');
                expect(user.emails[0].value).to.equal('jgilber@example.com');
                expect(user.emails[0].type).to.equal('work');
                expect(user.ims[0].value).to.equal('jgilber@example.com');
                expect(user.ims[0].type).to.equal('aim');
                expect(user.photos).to.equal(undefined);                                // deleted
                expect(user.groups[0].display).to.equal('UserGroup-1');
                expect(user.groups[0].value).to.equal('UserGroup-1');
                done();
            });
    });


    it('deleteUser test', (done) => {

        server_8880.delete('/Users/jgilber')
            .set(options.headers)
            .end(function (err, res) {
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


    it('createGroup test', (done) => {
        let newGroup = {
            displayName: 'Undead',
            id: 'Undead',
            externalId: undefined,
            members: [{
                value: 'bjensen',
                display: 'bjensen'
            }]
        };

        server_8880.post('/Groups')
            .set(options.headers)
            .send(newGroup)
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(201);
                expect(res.body.meta.location).to.equal('http://localhost:8880/Groups/Undead'); 
                done();
            });
    });


    it('getGroup just created test', (done) => {
        server_8880.get('/Groups/Undead')
            .set(options.headers)
            .end(function (err, res) {
                let group = res.body;
                expect(res.statusCode).to.equal(200);
                expect(group).to.not.equal('undefined');
                expect(group.displayName).to.equal('Undead');
                expect(group.id).to.equal('Undead');
                expect(group.members[0].value).to.equal('bjensen');
                expect(group.members[0].display).to.equal('bjensen');
                done();
            });
    });


    it('modifyGroupMembers test', (done) => {
        server_8880.patch('/Groups/Undead')
            .set(options.headers)
            .send({ "members": [{ "value": "jsmith" }, { "operation": "delete", "value": "bjensen" }], "schemas": ["urn:scim:schemas:core:1.0"] })
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(200);
                done();
            });
    });


    it('getGroup just modified members test', (done) => {
        server_8880.get('/Groups/Undead')
            .set(options.headers)
            .end(function (err, res) {
            let group = res.body;
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
