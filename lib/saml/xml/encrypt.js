const xmlenc = require('xml-encryption');

const utils = require('../utils');

exports.fromEncryptXmlOptions = function (options) {
  if (!options.encryptionCert) {
    return this.unencrypted;
  } else {
    const encryptOptions = {
      rsa_pub: options.encryptionPublicKey,
      pem: options.encryptionCert,
      encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: options.keyEncryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
      disallowEncryptionWithInsecureAlgorithm: options?.disallowEncryptionWithInsecureAlgorithm !== false,
      warnInsecureAlgorithm: options?.warnOnInsecureEncryptionAlgorithm !== false,
    };

    // expose the encryptOptions as these are needed when adding the SubjectConfirmation
    return Object.assign(this.encrypted(encryptOptions), { encryptOptions: encryptOptions });
  }
};

exports.unencrypted = function (xml, callback) {
  if (callback) {
    return setImmediate(callback, null, xml);
  } else {
    return xml;
  }
};

exports.encrypted = function (encryptOptions) {
  return function encrypt(xml, callback) {
    xmlenc.encrypt(xml, encryptOptions, function (err, encrypted) {
      if (err) {
        // Attempt to fix errors and retry
        xmlenc.encrypt(
            xml,
            {
              ...encryptOptions,
              rsa_pub: utils.fixPemFormatting(encryptOptions.rsa_pub),
              pem: utils.fixPemFormatting(encryptOptions.pem),
            },
            function (retryErr, retryEncrypted) {
              if (retryErr) {
                return callback(retryErr);
              }

              callback(null, utils.removeWhitespace(retryEncrypted));
            }
        );
      } else {
        callback(null, utils.removeWhitespace(encrypted));
      }
    });
  };
};
