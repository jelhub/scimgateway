import async from 'async'
import moment from 'moment'
import xmlNameValidator from 'xml-name-validator'
import { is_uri } from 'valid-url'

import * as EncryptXml from './xml/encrypt.js'
import * as SignXml from './xml/sign.js'
import * as utils from './utils.js'

var saml20Template = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="" IssueInstant="">' +
  '<saml:Issuer></saml:Issuer>' +
  '<saml:Subject>' +
  '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />' +
  '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
  '<saml:SubjectConfirmationData />' +
  '</saml:SubjectConfirmation>' +
  '</saml:Subject>' +
  '<saml:Conditions />' +
  '<saml:AuthnStatement AuthnInstant="">' +
  '<saml:AuthnContext>' +
  '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>' +
  '</saml:AuthnContext>' +
  '</saml:AuthnStatement>' +
  '</saml:Assertion>';

var newSaml20Document = utils.factoryForNode(saml20Template);

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

function getAttributeType(value){
  switch(typeof value) {
    case "string":
      return 'xs:string';
    case "boolean":
      return 'xs:boolean';
    case "number":
      return 'xs:double';
    default:
      return 'xs:anyType';
  }
}

function getNameFormat(name){
  if (is_uri(name)){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }

  if (xmlNameValidator.name(name).success){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
  }

  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
}

function extractSaml20Options(opts) {
  return {
    uid: opts.uid,
    issuer: opts.issuer,
    lifetimeInSeconds: opts.lifetimeInSeconds,
    audiences: opts.audiences,
    recipient: opts.recipient,
    inResponseTo: opts.inResponseTo,
    attributes: opts.attributes,
    includeAttributeNameFormat: (typeof opts.includeAttributeNameFormat !== 'undefined') ? opts.includeAttributeNameFormat : true,
    typedAttributes: (typeof opts.typedAttributes !== 'undefined') ? opts.typedAttributes : true,
    sessionIndex: opts.sessionIndex,
    nameIdentifier: opts.nameIdentifier,
    nameIdentifierFormat: opts.nameIdentifierFormat,
    authnContextClassRef: opts.authnContextClassRef
  };
}

/**
 * Creates a signed SAML 2.0 assertion from the given options.
 */
export const create = function createSignedAssertion(options, callback) {
  return createAssertion(extractSaml20Options(options), {
    signXml: SignXml.fromSignXmlOptions(Object.assign({
      xpathToNodeBeforeSignature: "//*[local-name(.)='Issuer']",
      signatureIdAttribute: 'ID'
    }, options)),
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
};

/**
 * Creates an unsigned SAML 2.0 assertion from the given options.
 */
export const createUnsignedAssertion = function createUnsignedAssertion(options, callback) {
  return createAssertion(extractSaml20Options(options), {
    signXml: SignXml.unsigned,
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
};

function createAssertion(options, strategies, callback) {
  var doc = newSaml20Document();

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  
    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }
  
  if (options.audiences) {
    var audienceRestriction = doc.createElementNS(NAMESPACE, 'saml:AudienceRestriction');
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      audienceRestriction.appendChild(element);
    });

    conditions[0].appendChild(audienceRestriction); 
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.createElementNS(NAMESPACE, 'saml:AttributeStatement');
    statement.setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
    statement.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
    doc.documentElement.appendChild(statement);
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;

      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);

      if (options.includeAttributeNameFormat){
        attributeElement.setAttribute('NameFormat', getNameFormat(prop));        
      }

      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        if (typeof value !== 'undefined') {
          var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
          valueElement.setAttribute('xsi:type', options.typedAttributes ? getAttributeType(value) : 'xs:anyType');
          valueElement.textContent = value;
          attributeElement.appendChild(valueElement);
        }
      });

      if (values && values.filter(function(i){ return typeof i !== 'undefined'; }).length > 0) {
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  if (options.sessionIndex) {
    doc.getElementsByTagName('saml:AuthnStatement')[0]
      .setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameID')[0];
  
  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }
  
  if( options.authnContextClassRef ) {
    doc.getElementsByTagName('saml:AuthnContextClassRef')[0]
      .textContent = options.authnContextClassRef;
  }

  if (strategies.encryptXml === EncryptXml.unencrypted) {
    var signed = strategies.signXml(doc);
    return strategies.encryptXml(signed, callback);
  }

  async.waterfall([
    function(cb) {
      strategies.signXml(doc, cb);
    },
    function(signed, cb) {
      strategies.encryptXml(signed, cb);
    }
  ], function (err, result) {
    if (err) return callback(err);
    callback(null, result);
  });
}
