var http = require('http');
process.chdir(__dirname);

exports.idleTest = function(test) {
	var spinner = require('..').createSpinner();

	//
	// spin the first time and register for 'stopped' event
	//

	var x = spin();

	x.on('stopped', function() {
		console.log('yeah! stopped!');
		test.done();
	});

	//
	// send 10 requests, while spinning
	// 

	var numberOfRequests = 5;

	function _sendRequest() {
		
		if (numberOfRequests-- <= 0) {
			console.log('3 seconds from now the child should be stopped because we stopped sending requests');
			return;
		}

		console.log(numberOfRequests + ' requests remaining');

		return spin(function(err, port) {
			test.ok(!err, err);
			test.ok(port);
			req(port, function(err, res) {
				test.ok(!err, err);
				return setTimeout(_sendRequest, 1000);
			});
		});
	}

	_sendRequest();

	function spin(callback) {
		return spinner.start({ script: 'scripts/normal', idleTimeSec: 3 }, callback);
	}
};

exports.testIdleWithLazyKiller = function(test) {
	var spinner = require('..').createSpinner();

	//
	// spin the first time and register for 'stopped' event
	//

	var x = spin();

	x.on('stopped', function() {
		console.log('yeah! stopped!');
		test.done();
	});

	//
	// send 10 requests, while spinning
	// 

	var numberOfRequests = 5;

	function _sendRequest() {
		
		if (numberOfRequests-- <= 0) {
			console.log('10 seconds from now the child should be stopped because we stopped sending requests');
			return;
		}

		console.log(numberOfRequests + ' requests remaining');

		return spin(function(err, port) {
			req(port, function(err, res) {
				return setTimeout(_sendRequest, 1000);
			});
		});
	}

	_sendRequest();

	function spin(callback) {
		return spinner.start({ script: 'scripts/lazykiller', idleTimeSec: 10 }, callback);
	}
};

// -- helpers

function req(port, callback) {
	var req = {};
	if (parseInt(port)) req = { port: port, host: 'localhost '};
	else req = { socketPath: port };
	
	http.get(req, function(response) { 
		return callback(null, response); 
	}).on('error', function(err) { 
		console.error(err);
		return callback(err); 
	});
}