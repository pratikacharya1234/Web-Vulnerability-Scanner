var uuid = require('node-uuid');

module.exports = function() {
	var map = {};
	var api = {};

	api.alloc = function(key, cb, logger) {
		logger = logger || console;
		var port = map[key];
		if (!port) {
			port = generateSocketName();
			map[key] = port;
		}

		return cb(null, port);
	};

	api.free = function(port, logger) {
		logger = logger || console;
		// nothing to free -- domain sockets are nice
		return true;
	};

	return api;
};

// -- private

var os = require('os');
var path = require('path');

function generateSocketName() {
	var n = uuid().replace(/-/g, '');

	var p;
	if (os.type().toLowerCase().indexOf('windows') !== -1) p = '\\\\.\\pipe\\' + n;
	else p = path.join('/tmp', n);

	return p;
}