'use strict'

// Natural language-like assertions
const expect = require('chai').expect;
const scimgateway = require('../../lib/plugin-loki.js');
const server_8880 = require('supertest').agent('http://localhost:8880'); // module request is an alternative

const auth = "Basic " + new Buffer('gwadmin:password').toString("base64");
var options = {
    headers: {
        'Content-Type': 'application/json',
        'Authorization': auth
    }
};


describe('plugin-loki tests', () => {


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
                expect(groups.totalResults).to.be.above(3);
                expect(groups.itemsPerPage).to.be.above(3);
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
                expect(user).to.not.equal(undefined);
                expect(user.id).to.equal('bjensen');
                expect(user.active).to.equal(true);
                expect(user.name.givenName).to.equal('Barbara');
                expect(user.name.familyName).to.equal('Jensen');
                expect(user.name.formatted).to.equal('Ms. Barbara J Jensen III');
                expect(user.entitlements[0].type).to.equal('newentitlement');
                expect(user.entitlements[0].value).to.equal('bjensen@example.com');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8377');
                expect(user.emails[0].type).to.equal('work');
                expect(user.emails[0].value).to.equal('bjensen@example.com');
                expect(user.meta.location).to.not.equal(undefined);
                expect(user.schemas).to.not.equal(undefined);
                done();
            });
    });


    it('getUser test (2)', function (done) {
        server_8880.get('/Users' +
            '?filter=userName eq "bjensen"&attributes=attributes=ims,locale,name.givenName,externalId,preferredLanguage,userType,id,title,timezone,name.middleName,name.familyName,nickName,name.formatted,meta.location,userName,name.honorificSuffix,meta.version,meta.lastModified,meta.created,name.honorificPrefix,emails,phoneNumbers,photos,x509Certificates.value,profileUrl,roles,active,addresses,displayName,entitlements')
            .set(options.headers)
            .end(function (err, res) {
                let user = res.body;
                user = user.Resources[0];
                expect(res.statusCode).to.equal(200);
                expect(user).to.not.equal(undefined);
                expect(user.id).to.equal('bjensen');
                expect(user.active).to.equal(true);
                expect(user.name.givenName).to.equal('Barbara');
                expect(user.name.familyName).to.equal('Jensen');
                expect(user.name.formatted).to.equal('Ms. Barbara J Jensen III');
                expect(user.entitlements[0].type).to.equal('newentitlement');
                expect(user.entitlements[0].value).to.equal('bjensen@example.com');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8377');
                expect(user.emails[0].type).to.equal('work');
                expect(user.emails[0].value).to.equal('bjensen@example.com');
                expect(user.meta.location).to.not.equal(undefined);
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
                // expect(group.members[0].display).to.equal('bjensen');
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
                // expect(groups.Resources[0].members[0].display).to.equal('bjensen');
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


    it('createUser test', (done) => {
        let newUser = {
            userName: 'jgilber',
            active: true,
            password: 'secretpassword',
            name: {
                formatted: 'Mr. Jeff Gilbert',
                familyName: 'Gilbert',
                givenName: 'Jeff'
            },
            title: 'test title',
            emails: [{
                "value": 'jgilber@example.com',
                "type": 'work'
            }],
            phoneNumbers: [{
                value: 'tel:555-555-8376',
                type: 'work'
            }],
            entitlements: [{
                value: 'Test Company',
                type: 'company'
            }],
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
                expect(user).to.not.equal(undefined);
                expect(user.id).to.equal('jgilber');
                expect(user.active).to.equal(true);
                expect(user.name.givenName).to.equal('Jeff');
                expect(user.name.familyName).to.equal('Gilbert');
                expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
                expect(user.title).to.equal('test title');
                expect(user.emails[0].type).to.equal('work');
                expect(user.emails[0].value).to.equal('jgilber@example.com');
                expect(user.entitlements[0].type).to.equal('company');
                expect(user.entitlements[0].value).to.equal('Test Company');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
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
                type: 'work'
            }],
            emails: [{
                operation: "delete",
                value: 'jgilber@example.com',
                type: 'work'
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
                expect(user).to.not.equal(undefined);
                expect(user.id).to.equal('jgilber');
                expect(user.active).to.equal(false);                        // modified
                expect(user.name.givenName).to.equal('Jeff-Modified');      // modified
                expect(user.name.familyName).to.equal(undefined);           // cleared
                expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
                expect(user.title).to.equal('test title');
                expect(user.emails).to.equal(undefined);                    // deleted
                expect(user.entitlements[0].type).to.equal('company');
                expect(user.entitlements[0].value).to.equal('Test Company');
                expect(user.phoneNumbers[0].type).to.equal('work');
                expect(user.phoneNumbers[0].value).to.equal('tel:123');     // modiied
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


    it('createGroup test', (done) => {
        let newGroup = {
            displayName: 'GoGoLoki',
            externalId: undefined,
            members: [{
                value: 'bjensen'
            }]
        };

        server_8880.post('/Groups')
            .set(options.headers)
            .send(newGroup)
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(201);
                expect(res.body.meta.location).to.equal('http://localhost:8880/Groups/GoGoLoki');
                done();
            });
    });


    it('getGroup just created test', (done) => {
        server_8880.get('/Groups/GoGoLoki')
            .set(options.headers)
            .end(function (err, res) {
                let group = res.body;
                expect(res.statusCode).to.equal(200);
                expect(group).to.not.equal('undefined');
                expect(group.displayName).to.equal('GoGoLoki');
                expect(group.id).to.equal('GoGoLoki');
                done();
            });
    });


    it('modifyGroupMembers test', (done) => {
        server_8880.patch('/Groups/GoGoLoki')
            .set(options.headers)
            .send({ "members": [{ "value": "xman" }, { "value": "zperson" }], "schemas": ["urn:scim:schemas:core:1.0"] })
            .end(function (err, res) {
                expect(err).to.equal(null);
                expect(res.statusCode).to.equal(200);
                done();
            });
    });


    it('getGroup just modified members test', (done) => {
        server_8880.get('/Groups/GoGoLoki')
            .set(options.headers)
            .end(function (err, res) {
                let group = res.body;
                expect(res.statusCode).to.equal(200);
                expect(group).to.not.equal('undefined');
                expect(group.displayName).to.equal('GoGoLoki');
                expect(group.id).to.equal('GoGoLoki');
                expect(group.members.length).to.equal(3);
                expect(group.members[1].value).to.equal('xman');
                expect(group.members[2].value).to.equal('zperson');
                done();
            });
    });


});

