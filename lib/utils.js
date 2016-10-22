//==================================
// File:    util.js
//
// Author:  Jarle Elshaug
//==================================

module.exports.getPassword = function (pwDotNotation, configFile) {
    //Get password from json-file.
    //If cleartext then encrypt and save the new encrypted password

    Object.prop = function (obj, prop, val) {
        var props = prop.split('.')
            , final = props.pop(), p
        while (p = props.shift()) {
            if (typeof obj[p] === 'undefined')
                return undefined;
            obj = obj[p]
        }
        return val ? (obj[final] = val) : obj[final]
    }

    var chi = require('path').basename(configFile) + require('os').hostname();
    var crypto = require('crypto');
    var decipher = crypto.createDecipher('aes192', chi);
    var cipher = crypto.createCipher('aes192', chi);
    var fs = require('fs');
    var configString = configString = fs.readFileSync(configFile).toString();
    var config = JSON.parse(configString);
    //var pw = eval('config.' + pwDotNotation); //eval not always the best (use Object.prop)
    var pw = Object.prop(config, pwDotNotation);
    if (pw != undefined) {
        try {
            //Decrypt
            decipher.update(pw, 'hex');
            pw = decipher.final('utf8');
        } catch (err) {
            if ((err.message.indexOf('Bad input string') == 0) || (err.message.indexOf('wrong final block length') > -1)) {
                //Password is cleartext and needs to be encrypted and written back to file
                //Encrypt
                cipher.update(pw);
                var pwencr = cipher.final('hex');
                //Update new password in config file 
                //eval('config.' + pwDotNotation + '="' + pwencr + '"'); //don't use eval
                Object.prop(config, pwDotNotation, pwencr)
                var fileContent = JSON.stringify(config, null, 4); // Removing white space, but use 4 space separator      
                fileContent = fileContent.replace(/\n/g, '\r\n'); // cr-lf instead of lf
                try {
                    fs.writeFileSync(configFile, fileContent);
                } catch (err) {
                    throw err;
                }
            } else {
                //Something went wrong, return empty password
                pw = '';
            }
        }
    } else {
        //undefined means password attribute/key not found in config file
        var err = new Error(pwDotNotation + ' can not be found in configuration file ' + configFile);
        throw (err);

    }

    return pw;

} //getPassword
