//
// Copy plugins from original scimgateway package to current installation folder
//
var fs = require('fs');

if (fs.existsSync('./node_modules')) return true; // global package - quit - no postinstall

if (!fs.existsSync('../../config')) fs.mkdirSync('../../config');
if (!fs.existsSync('../../config/certs')) fs.mkdirSync('../../config/certs');
if (!fs.existsSync('../../config/wsdls')) fs.mkdirSync('../../config/wsdls');
if (!fs.existsSync('../../lib')) fs.mkdirSync('../../lib');

fs.writeFileSync('../../config/plugin-testmode.json', fs.readFileSync('./config/plugin-testmode.json'));
fs.writeFileSync('../../config/plugin-restful.json', fs.readFileSync('./config/plugin-restful.json'));
fs.writeFileSync('../../config/plugin-forwardinc.json', fs.readFileSync('./config/plugin-forwardinc.json'));
fs.writeFileSync('../../config/plugin-saphana.json', fs.readFileSync('./config/plugin-mssql.json'));
fs.writeFileSync('../../config/plugin-saphana.json', fs.readFileSync('./config/plugin-saphana.json'));

fs.writeFileSync('../../lib/plugin-testmode.js', fs.readFileSync('./lib/plugin-testmode.js'));
fs.writeFileSync('../../lib/plugin-restful.js', fs.readFileSync('./lib/plugin-restful.js'));
fs.writeFileSync('../../lib/plugin-forwardinc.js', fs.readFileSync('./lib/plugin-forwardinc.js'));
fs.writeFileSync('../../lib/plugin-saphana.js', fs.readFileSync('./lib/plugin-mssql.js'));
fs.writeFileSync('../../lib/plugin-saphana.js', fs.readFileSync('./lib/plugin-saphana.js'));

if (!fs.existsSync('../../config/wsdls/GroupService.wsdl'))
    fs.writeFileSync('../../config/wsdls/GroupService.wsdl', fs.readFileSync('./config/wsdls/GroupService.wsdl'));
if (!fs.existsSync('../../config/wsdls/UserService.wsdl'))
    fs.writeFileSync('../../config/wsdls/UserService.wsdl', fs.readFileSync('./config/wsdls/UserService.wsdl'));

fs.writeFileSync('../../README.html', fs.readFileSync('./README.html'));
fs.writeFileSync('../../LICENSE', fs.readFileSync('./LICENSE'));
if (!fs.existsSync('../../index.js')) fs.writeFileSync('../../index.js', fs.readFileSync('./index.js'));
