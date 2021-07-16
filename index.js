const path = require("path");

module.exports.load = function load(pluginName) {
  return require(path.join(__dirname, "lib", pluginName));
};