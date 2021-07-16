module.exports.load = function load(pluginName) {
  return require(path.join("lib", pluginName));
};
