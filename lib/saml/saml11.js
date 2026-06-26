var utils = require('./utils');
var Parser = require('@xmldom/xmldom').DOMParser;
var xmlenc = require('xml-encryption');
var moment = require('moment');
var async = require('async');
var crypto = require('crypto');

var EncryptXml = require('./xml/encrypt');
var SignXml = require('./xml/sign');

var saml11Template = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="" IssueInstant="">' +
  '<saml:Conditions>' +
  '<saml:AudienceRestrictionCondition />' +
  '</saml:Conditions>' +
  '<saml:AttributeStatement>' +
  '<saml:Subject>' +
  '<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />' +
  '<saml:SubjectConfirmation>' +
  '<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>' +
  '</saml:SubjectConfirmation>' +
  '</saml:Subject>' +
  '</saml:AttributeStatement>' +
  '<saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password">' +
  '<saml:Subject>' +
  '<saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' +
  '</saml:NameIdentifier>' +
  '<saml:SubjectConfirmation>' +
  '<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>' +
  '</saml:SubjectConfirmation>' +
  '</saml:Subject>' +
  '</saml:AuthenticationStatement>' +
  '</saml:Assertion>';

var newSaml11Document = utils.factoryForNode(saml11Template);

var NAMESPACE = 'urn:oasis:names:tc:SAML:1.0:assertion';

function extractSaml11Options(opts) {
  return {
    uid: opts.uid,
    issuer: opts.issuer,
    lifetimeInSeconds: opts.lifetimeInSeconds,
    audiences: opts.audiences,
    attributes: opts.attributes,
    nameIdentifier: opts.nameIdentifier,
    nameIdentifierFormat: opts.nameIdentifierFormat,
    subjectConfirmationMethod: opts.subjectConfirmationMethod,
    holderOfKeyProofSecret: opts.holderOfKeyProofSecret,
  };
}

/**
 * Creates a signed SAML 1.1 assertion from the given options.
 */
exports.create = function(options, callback) {
  return createAssertion(extractSaml11Options(options), {
    signXml: SignXml.fromSignXmlOptions(Object.assign({
      xpathToNodeBeforeSignature: "//*[local-name(.)='AuthenticationStatement']",
      signatureIdAttribute: 'AssertionID'
    }, options)),
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
}

/**
 * Creates an unsigned SAML 1.1 assertion from the given options.
 */
exports.createUnsignedAssertion = function(options, callback) {
  return createAssertion(extractSaml11Options(options), {
    signXml: SignXml.unsigned,
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
}

function createAssertion(options, strategies, callback) {
  var doc;
  try {
    doc = newSaml11Document();
  } catch(err){
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('AssertionID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer)
    doc.documentElement.setAttribute('Issuer', options.issuer);

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', moment(now).add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }

  if (options.audiences) {
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestrictionCondition')[0];
      audienceCondition.appendChild(element);
    });
  }

  if (options.attributes) {
    var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'AttributeStatement')[0];
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;

      var name = prop.indexOf('/') > -1 ? prop.substring(prop.lastIndexOf('/') + 1) : prop;
      var namespace = prop.indexOf('/') > -1 ? prop.substring(0, prop.lastIndexOf('/')) : '';
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('AttributeNamespace', namespace);
      attributeElement.setAttribute('AttributeName', name);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      if (values && values.length > 0) {
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthenticationStatement')[0]
    .setAttribute('AuthenticationInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;

    doc.getElementsByTagName('saml:AuthenticationStatement')[0]
      .getElementsByTagName('saml:NameIdentifier')[0]
      .textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    var nameIDs = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier');
    nameIDs[0].setAttribute('Format', options.nameIdentifierFormat);
    nameIDs[1].setAttribute('Format', options.nameIdentifierFormat);
  }

  if (strategies.encryptXml === EncryptXml.unencrypted) {
    var signed = strategies.signXml(doc);
    return strategies.encryptXml(signed, callback);
  }

  // encryption is turned on,
  var proofSecret;
  async.waterfall([
    function (cb) {
      if (!options.subjectConfirmationMethod && options.subjectConfirmationMethod !== 'holder-of-key')
        return cb();

      crypto.randomBytes(32, function(err, randomBytes) {
        proofSecret = randomBytes;
        addSubjectConfirmation(strategies.encryptXml.encryptOptions, doc, options.holderOfKeyProofSecret || randomBytes, cb);
      });
    },
    function(cb) {
      strategies.signXml(doc, cb);
    },
    function(signed, cb) {
      strategies.encryptXml(signed, cb);
    }
  ], function (err, result) {
    if (err) return callback(err);
    callback(null, result, proofSecret);
  });
}

function addSubjectConfirmation(encryptOptions, doc, randomBytes, callback) {
  xmlenc.encryptKeyInfo(randomBytes, encryptOptions, function(err, keyinfo) {
    if (err) return callback(err);
    var subjectConfirmationNodes = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'SubjectConfirmation');

    for (var i=0; i<subjectConfirmationNodes.length; i++) {
      var keyinfoDom;
      try {
        keyinfoDom = new Parser().parseFromString(keyinfo);
      } catch(error){
        return utils.reportError(error, callback);
      }

      var method = subjectConfirmationNodes[i].getElementsByTagNameNS(NAMESPACE, 'ConfirmationMethod')[0];
      method.textContent = 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key';
      subjectConfirmationNodes[i].appendChild(keyinfoDom.documentElement);
    }

    callback();
  });
}
