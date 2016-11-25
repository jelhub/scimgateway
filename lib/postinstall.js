var fs = require('fs');
if (!fs.existsSync('../../config')) fs.mkdirSync('../../config');
if (!fs.existsSync('../../config/certs')) fs.mkdirSync('../../config/certs');
if (!fs.existsSync('../../config/wsdls')) fs.mkdirSync('../../config/wsdls');
if (!fs.existsSync('../../lib')) fs.mkdirSync('../../lib');

fs.writeFileSync('../../config/plugin-testmode.json', fs.readFileSync('./config/plugin-testmode.json'));
fs.writeFileSync('../../config/plugin-forwardinc.json', fs.readFileSync('./config/plugin-forwardinc.json'));
fs.writeFileSync('../../config/plugin-saphana.json', fs.readFileSync('./config/plugin-saphana.json'));

fs.writeFileSync('../../lib/plugin-testmode.js', fs.readFileSync('./lib/plugin-testmode.js'));
fs.writeFileSync('../../lib/plugin-forwardinc.js', fs.readFileSync('./lib/plugin-forwardinc.js'));
fs.writeFileSync('../../lib/plugin-saphana.js', fs.readFileSync('./lib/plugin-saphana.js'));

fs.writeFileSync('../../README.html', fs.readFileSync('./README.html'));
fs.writeFileSync('../../LICENSE', fs.readFileSync('./LICENSE'));
if (!fs.existsSync('../../index.js')) fs.writeFileSync('../../index.js', fs.readFileSync('./index.js'));
