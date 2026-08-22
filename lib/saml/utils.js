import { DOMParser as Parser } from '@xmldom/xmldom'

export const pemToCert = function(pem) {
  const cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert && cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};

export const reportError = function(err, callback){
  if (callback){
    setImmediate(function(){
      callback(err);
    });
  }
};

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */
export const uid = function(len) {
  const buf = []
      , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
      , charlen = chars.length;

  for (let i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

export const removeWhitespace = function(xml) {
  return xml
      .replace(/\r\n/g, '')
      .replace(/\n/g, '')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

/**
 * Return a random int, used by `utils.uid()`
 *
 * @param {Number} min
 * @param {Number} max
 * @return {Number}
 * @api private
 */

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Returns a function that can be called to create a new Node from an inline template string.
 *
 * @param {string} templateString the XML template content
 * @return {function(): Node}
 */
export const factoryForNode = function factoryForNode(templateString) {
  const prototypeDoc = new Parser().parseFromString(templateString);

  return function () {
    return prototypeDoc.cloneNode(true);
  };
};

/**
 * Standardizes PEM content to match the spec (best effort)
 *
 * @param pem {Buffer} The PEM content to standardize
 * @returns {Buffer} The standardized PEM. Original will be returned unmodified if the content is not PEM.
 */
export const fixPemFormatting = function (pem) {
  let pemEntries = pem.toString().matchAll(/([-]{5}[^-\r\n]+[-]{5})([^-]*)([-]{5}[^-\r\n]+[-]{5})/g);
  let fixedPem = ''
  for (const pemParts of pemEntries) {
    fixedPem = fixedPem.concat(`${pemParts[1]}\n${pemParts[2].replaceAll(/[\r\n]/g, '')}\n${pemParts[3]}\n`)
  }
  if (fixedPem.length === 0) {
    return pem;
  }

  return Buffer.from(fixedPem)
}
