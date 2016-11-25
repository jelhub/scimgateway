//==============================================================
// File:    logger.js
//
// Author:  Jarle Elshaug
//==============================================================

module.exports = function (loglevel, logfile) {
    var module = {};
    var winston = require('winston');
    winston.emitErrs = true;

    //level: silly=0(lowest), debug=1, verbose=2, info=3, warn=4, error=5(highest)

    //2 hours wrong time if not setting timestamp. Timezone did not work.
    //moment-timezone is also an alternative to the timestamp() function.
    function timestamp() {
        function pad(n) { return n < 10 ? "0" + n : n }
        var d = new Date();
        return d.getFullYear() + '-' +
            pad(d.getMonth() + 1) + '-' +
            pad(d.getDate()) + 'T' +
            pad(d.getHours()) + ':' +
            pad(d.getMinutes()) + ':' +
            pad(d.getSeconds()) + '.' +
            pad(d.getMilliseconds())
    }


    module.logger = new winston.Logger({
        filters: [function (level, msg, meta) {
            // mask json (scim) password
            var rePattern = new RegExp(/^.*"password":"([^"]+)".*$/);
            var arrMatches = msg.match(rePattern);
            if (Array.isArray(arrMatches) && arrMatches.length === 2) {
                arrMatches[1] = arrMatches[1].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'); // escaping special regexp characters
                msg = msg.replace(new RegExp(arrMatches[1], 'g'), '********');
            }
            // mask xml (soap) credentials, PasswordText or PasswordDigest
            rePattern = new RegExp(/^.*(credentials"?|PasswordText"?|PasswordDigest"?)>([^<]+)<.*$/);
            arrMatches = msg.match(rePattern);
            if (Array.isArray(arrMatches) && arrMatches.length === 3) {
                arrMatches[2] = arrMatches[2].replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                msg = msg.replace(new RegExp('>' + arrMatches[2] + '<', 'g'), '>********<');
            }
            return msg;
        }],
        transports: [
            new winston.transports.File({
                level: loglevel || 'error',
                filename: logfile,
                timestamp: function () { return timestamp() },
                handleExceptions: true,
                json: false,
                maxsize: 5242880, //5MB
                maxFiles: 5,
                colorize: false,
            }),
            new winston.transports.Console({
                level: 'error',
                handleExceptions: true,
                json: false,
                colorize: true,
            })
        ],
        exitOnError: false
    });


    // flush to disk before exit (process.exit in main code will terminate logger and we may have unflushed logfile updates)
    // note, still asynchronous (using exception is an alternative that gives synchronous flush and program exit)
    module.logger.exitAfterFlush = function (code) {
        module.logger.transports.file.on('flush', function () {
            process.exit(code);
        });
    };


    module.stream = {
        write: function (message, encoding) {
            module.logger.info(message);
        }
    };

    return module;
};

