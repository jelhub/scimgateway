'use strict'

// Natural language-like assertions
const expect = require('chai').expect;
const scimgateway = require('../../lib/plugin-testmode.js');

describe('plugin-testmode tests', () => {

    it('getUser test', (done) => {
        let user = undefined;
        scimgateway.emit('getUser', 'req.params.baseEntity', 'bjensen', null, function (err, data) {
            user = data;
        });
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
        expect(user.meta.location).to.equal('http://localhost:8880/v1/Users/bjensen');
        expect(user.meta.version).to.equal('"20160111084221.596Z"');
        done();
    });


    it('exploreUsers test', (done) => {
        let users = undefined;
        scimgateway.emit('exploreUsers', 'req.params.baseEntity', 1, 10, function (err, data) {
            users = data;
        });

        expect(users).to.not.equal('undefined');
        expect(users.Resources[0].userName).to.equal('bjensen');
        expect(users.Resources[0].id).to.equal('bjensen');
        done();
    });


    it('exploreGroups test', (done) => {
        let groups = undefined;
        scimgateway.emit('exploreGroups', 'req.params.baseEntity', 1, 10, function (err, data) {
            groups = data;
        });

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

    it('getGroup test', (done) => {
        let group = undefined;
        scimgateway.emit('getGroup', 'req.params.baseEntity', 'Admins', '', function (err, data) {
            group = data;
        });
        expect(group).to.not.equal('undefined');
        expect(group.displayName).to.equal('Admins');
        expect(group.id).to.equal('Admins');
        expect(group.members[0].value).to.equal('bjensen');
        expect(group.members[0].display).to.equal('bjensen');
        done();
    });

    it('getGroupMembers test', (done) => {
        let groupMembers = undefined;
        scimgateway.emit('getGroupMembers', 'req.params.baseEntity', 'bjensen', '', 1, 10, function (err, data) {
            groupMembers = data;
        });
        expect(groupMembers).to.not.equal('undefined');
        expect(groupMembers.Resources[0].displayName).to.equal('Admins');
        expect(groupMembers.Resources[0].members[0].value).to.equal('bjensen');
        expect(groupMembers.Resources[0].totalResults).to.equal(groupMembers.Resources[0].members[0].length);
        done();
    });

    it('getGroupUsers test', (done) => {
        let groupUsers = undefined;
        scimgateway.emit('getGroupUsers', 'req.params.baseEntity', 'UserGroup-1', '', function (err, data) {
            groupUsers = data;
        });
        expect(groupUsers).to.not.equal('undefined');
        expect(groupUsers[0].userName).to.equal('bjensen');
        done();
    });


    it('convertedScim test', (done) => {
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
            }]
        };

        user = scimgateway.convertedScim(user); // multivalue array to none-array based on type
      
        expect(user).to.not.equal('undefined');
        expect(user.entitlements.newentitlement.value).to.equal('jgilber@example.com');
        expect(user.entitlements.newentitlement.type).to.equal('newentitlement');
        expect(user.entitlements.anotherentitlement.value).to.equal('nobody@example.com');
        expect(user.entitlements.anotherentitlement.type).to.equal('anotherentitlement');
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
        expect(user.name.familyName).to.equal('Gilbert');
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
        expect(user.groups[0].display).to.equal('UserGroup-1'); // groups not converted
        expect(user.groups[0].value).to.equal('UserGroup-1');
        done();
    });


    it('createUser test', (done) => {
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
        let returnValue = undefined;
        newUser = scimgateway.convertedScim(newUser); // multivalue array to none-array based on type
        scimgateway.emit('createUser', 'req.params.baseEntity', newUser, function (err, data) {
            expect(err).to.equal(null);
            returnValue = data;
        });
        expect(returnValue).to.not.equal('undefined');
        done();
    });


    it('getUser just created test', (done) => {
        let user = undefined;
        scimgateway.emit('getUser', 'req.params.baseEntity', 'jgilber', null, function (err, data) {
            user = data;
        });
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

    it('modifyUser test', (done) => {
        let user = {
             name: {
                givenName: 'Jeff-Modified'
            },
            active: false,
            phoneNumbers: [{
                value: 'tel:911',
                type: 'home'
            }],
            photos: [{
                operation: "delete",
                value: 'jgilber@example.com',
                type: 'photo'
            }],
        };
        let returnValue = undefined;
        user = scimgateway.convertedScim(user); // multivalue array to none-array based on type
        scimgateway.emit('modifyUser', 'req.params.baseEntity', 'jgilber', user, function (err, data) {
            expect(err).to.equal(null);
            returnValue = data;
        });
        expect(returnValue).to.not.equal('undefined');
        done();
    });


    it('getUser just modified test', (done) => {
        let user = undefined;
        scimgateway.emit('getUser', 'req.params.baseEntity', 'jgilber', null, function (err, data) {
            user = data;
        });
        expect(user).to.not.equal('undefined');
        expect(user.entitlements[0].value).to.equal('jgilber@example.com');
        expect(user.entitlements[0].type).to.equal('newentitlement');
        expect(user.name.formatted).to.equal('Mr. Jeff Gilbert');
        expect(user.name.familyName).to.equal('Gilbert');
        expect(user.name.givenName).to.equal('Jeff-Modified');                  // modified
        expect(user.x509Certificates[0].value).to.equal('jgilber@example.com');
        expect(user.x509Certificates[0].type).to.equal('cert');
        expect(user.active).to.equal(false);                                    // modified
        expect(user.phoneNumbers[0].value).to.equal('tel:555-555-8376');
        expect(user.phoneNumbers[0].type).to.equal('work');
        expect(user.phoneNumbers[1].value).to.equal('tel:911');                 // added
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


    it('deleteUser test', (done) => {
        let returnValue = undefined;
        scimgateway.emit('deleteUser', 'req.params.baseEntity', 'jgilber', function (err, data) {
            expect(err).to.equal(null);
            returnValue = data;
        });
        expect(returnValue).to.not.equal('undefined');
        done();
    });


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
        let returnValue = undefined;
        scimgateway.emit('createGroup', 'req.params.baseEntity', newGroup, function (err, data) {
            expect(err).to.equal(null);
            returnValue = data;
        });
        expect(returnValue).to.not.equal('undefined');
        done();
    });

    it('getGroup new group test', (done) => {
        let group = undefined;
        scimgateway.emit('getGroup', 'req.params.baseEntity', 'Undead', '', function (err, data) {
            group = data;
        });
        expect(group).to.not.equal('undefined');
        expect(group.displayName).to.equal('Undead');
        expect(group.id).to.equal('Undead');
        expect(group.members[0].value).to.equal('bjensen');
        expect(group.members[0].display).to.equal('bjensen');
        done();
    });

    it('modifyGroupMembers test', (done) => {
        let returnValue = undefined;
        scimgateway.emit('modifyGroupMembers', 'req.params.baseEntity', 'Undead', [{ "operation": "delete", "value": "bjensen" }], function (err, data) {
            expect(err).to.equal(null);
            returnValue = data;
        });
        expect(returnValue).to.not.equal('undefined');
        done();
    });

});
