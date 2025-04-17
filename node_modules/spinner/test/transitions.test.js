var async = require('async');
var fs = require('fs');
var path = require('path');
var logule = require('logule');
var http = require('http');

function createTests() {
	var GOOD_APP = "require('http').createServer(function(req, res) { return res.end($BODY); }).listen(process.env.PORT);console.log('bound');";
	var BAD_APP = "<BAD!>";
	var TAKE_YOUR_TIME_APP = "setTimeout(function() {" + GOOD_APP + "}, $TIMEOUT);";
	var LATE_DEATH = GOOD_APP + "setTimeout(function() { console.warn('bye!'); process.kill(2); }, $DIE_AFTER);";

	// -- helpers

	function series(test, fns) {
		return async.series(fns, function(err) {
			test.ok(!err, err);
			test.done();
		});
	}

	// -- tests
	return require('nodeunit').testCase({
		setUp: function(cb) {
			try {
			var self = this;

			var spinner = require('..').createSpinner({ logger: logule, fsmTraces: false });
			var tmpdir = path.join(process.env.TEMP || '/tmp', Math.round(Math.random() * 1000000) + ".test");
			fs.mkdirSync(tmpdir);

			self.tmpdir = tmpdir;
			self.spinner = spinner;
			self.logger = console;

			self.path = function(filename) { 
				return path.join(self.tmpdir, filename);
			};

			self.write = function(filename, data, fields) {
				return function(cb) {
					for (var k in fields) {
						data = data.replace(k, fields[k]);
					}
					self.logger.log('writing', filename, '[', data, ']');
					return fs.writeFile(self.path(filename), data, function() {
						return setTimeout(cb, 1000);
					});
				};
			};

			self.delay = function(delay, fn) {
				return function(cb) {
					return setTimeout(function() {
						return fn(cb);
					}, delay);
				};
			};

			self.start = function(filename, expect) {
				return function(cb) {
					self.logger.log('starting', filename);
					return self.spinner.start(self.path(filename), function(err, port) {
						if (expect) expect(err, port);
						return cb();
					});
				};
			};

			self.stop = function(filename) {
				return function(cb) {
					self.logger.log('stopping', filename);
					return self.spinner.stop(self.path(filename), cb);
				};
			};

			self.waitForFailure = function(filename) {
				return function(cb) {
					return self.request(filename, function(err, res, body) {
						if (!err) return self.waitForFailure(filename)(cb);
						return cb();
					});
				};
			};

			self.request = function(filename, cb) {
				self.logger.log('pinging', filename);
				var p = self.path(filename);
				var spnr = self.spinner.get(p);
				if (!spnr) return cb(new Error('unable to find spinner for ' + p));
				var port = spnr.port;
				if (!port) return cb(new Error('no port allocated for app'));

				// check if this is a domain socket or a regular socket.
				var req = {};
				if (parseInt(port)) {
					req = { port: port, host: 'localhost '};
				}
				else {
					req = { socketPath: port };
				}

				return http.get({ port: port }, function(res) {
					var buff = '';
					res.on('data', function(data) {
						buff += data.toString();
					});
					res.on('end', function() {
						res.body = buff;
						return cb(null, res);
					});
				}).on('error', function(err) {
					return cb(err);
				});
			}

			self.waitForSuccess = function(filename, expectedBody) {
				return function(cb) {
					self.request(filename, function(err, res, body) {
						if (err && err.code === 'ECONNREFUSED') {
							self.logger.log('connection refused, trying again in 1sec');
							return setTimeout(function() {
								var fn = self.waitForSuccess(filename, expectedBody);
								return fn(cb);
							}, 1000);
						}

						if (err) return cb(new Error(err));
						if (!res) return cb(new Error("no response"));

						self.logger.log('response: ', res.statusCode, res.body);
						if (res.statusCode !== 200) return cb(new Error("expecting 200 OK"));
						if (res.body !== expectedBody) return cb(new Error("expecting " + expectedBody + " in body. got " + res.body));
						return cb();
					});
				};
			};

			return cb();
			} catch(e) { console.error(e); };
		},

		tearDown: function(cb) {
			var self = this;
			self.spinner.stopall();
			return cb();
		},

		/**
		 * 1. app loads successfuly
		 * 2. app changes so now it cannot be loaded
		 * 3. monitor picks up change and restarts the app
		 * 4. an error is emitted but we expect it not to fail the process (bug)
		 * 5. app is fixed
		 * 6. we expect the monitor to picks the change again and restart again
		 * 7. now it should be up and running
		 */
		reloadAfterFailure: function(test) {
			var self = this;
			return series(test, [
				
				//
				// create an app that returns "1" on http requests
				//

				self.write("app.js", GOOD_APP, { $BODY: '"1"' }),

				self.start("app.js", function(err, port) {
					test.ok(!err, "expecting success");
					test.ok(port, "expecint a port to be allocated and returned");
				}),

				self.waitForSuccess('app.js', '1'),

				//
				// modify it so it now returns "2"
				//

				self.write('app.js', GOOD_APP, { $BODY: '"2"' }),
				self.waitForSuccess('app.js', '2'),

				//
				// screw up with the app and expect the process to move to 'faulted'
				//

				self.write('app.js', BAD_APP),

				// ping until failure
				self.waitForFailure('app.js'),

				//
				// now, fix the app and expect a recycle to happen
				//

				self.write('app.js', GOOD_APP, { $BODY: '"3"' }),
				
				self.waitForSuccess('app.js', '3'),

			]);
		},

		//
		// Stopped
		//

		startWhileStopped: function(test) {
			var self = this;
			return series(test, [
				self.write('joo.js', GOOD_APP, { $BODY: '"o"' }),
				self.start('joo.js'),
				self.waitForSuccess('joo.js', 'o'),
				self.stop('joo.js'),
				self.waitForFailure('joo.js'),
				self.start('joo.js'),
				self.waitForSuccess('joo.js', 'o'),
			]);
		},

		stopWhileStopped: function(test) {
			var self = this;
			return series(test, [
				self.write('joo.js', GOOD_APP, { $BODY: '"o"' }),
				self.start('joo.js'),
				self.waitForSuccess('joo.js', 'o'),
				self.stop('joo.js'),
				self.waitForFailure('joo.js'),
				self.stop('joo.js'),
				self.waitForFailure('joo.js'),
			]);
		},

		termWhileStopped: function(test) {
			var self = this;
			// this is an invalid state and impossible to simulate in black box
			test.done();
		},

		changeWhileStopped: function(test) {
			var self = this;
			return series(test, [
				self.write('joo.js', GOOD_APP, { $BODY: '"o"' }),
				self.start('joo.js'),
				self.waitForSuccess('joo.js', 'o'),
				self.stop('joo.js'),
				self.write('joo.js', GOOD_APP, { $BODY: '"p"' }),
				self.delay(2000, self.waitForFailure('joo.js')),
				self.start('joo.js'),
				self.waitForSuccess('joo.js', 'p'),
			]);
		},

		//
		// Starting
		//

		startWhileStarting: function(test) {
			var self = this;
			return series(test, [
				self.write('foo.js', GOOD_APP, { $BODY: '"x"' }),
				self.start('foo.js'),
				self.start('foo.js'),
				self.waitForSuccess('foo.js', 'x'),
			]);
		},

		stopWhileStarting: function(test) {
			var self = this;
			return series(test, [
				self.write('foo.js', GOOD_APP, { $BODY: '"x"' }),
				self.start('foo.js'),
				self.stop('foo.js'),
				self.waitForFailure('foo.js'),
			]);
		},

		termWhileStarting: function(test) {
			var self = this;
			return series(test, [
				self.write('goo.js', BAD_APP),
				self.start('goo.js'),
				self.waitForFailure(),
			]);
		},

		changeWhileStarting: function(test) {
			var self = this;
			return series(test, [
				self.write('loo.js', GOOD_APP, { $BODY: '"5"' }),
				self.start('loo.js'),
				self.write('loo.js', GOOD_APP, { $BODY: '"6"' }),
				self.waitForSuccess('loo.js', '6'),
			]);
		},

		//
		// Binding
		//

		startWhileBinding: function(test) {
			var self = this;
			return series(test, [
				self.write('moo.js', TAKE_YOUR_TIME_APP, { $BODY: '"0"', $TIMEOUT: 2000 }),
				self.start('moo.js'),
				self.delay(1000, self.start('moo.js')),
				self.waitForSuccess('moo.js', '0'),
			]);
		},

		stopWhileBinding: function(test) {
			var self = this;
			return series(test, [
				self.write('zoo.js', TAKE_YOUR_TIME_APP, { $BODY: '"H"', $TIMEOUT: 2000 }),
				self.start('zoo.js'),
				self.delay(1000, self.stop('zoo.js')),
				self.waitForFailure('zoo.js'),
			]);
		},

		termWhileBinding: function(test) {
			var self = this;
			return series(test, [
				self.write('too.js', BAD_APP),
				self.start('too.js'),
				self.waitForFailure('too.js'),
				self.start('too.js'), // try to start again, expect a failure
				self.waitForFailure('too.js'),

				// now change the app to be good and expect it will succeed
				self.write('too.js', GOOD_APP, { $BODY: '"GOOD"' }),
				self.waitForSuccess('too.js', 'GOOD'),
			]);
		},

		/**
		 * 1. start app which takes 10 seconds to bind
		 * 2. after 2 seconds, change it
		 * 3. expect that the final result will be that the new app is spawned
		 */
		changeWhileBinding: function(test) {
			var self = this;
			return series(test, [
				self.write('hanger.js', TAKE_YOUR_TIME_APP, { $BODY: '"A"', $TIMEOUT: 2000 } ),
				self.start('hanger.js'),
				self.waitForSuccess('hanger.js', 'A'),

				// change app, wait 1 second and change it again
				self.write('hanger.js', TAKE_YOUR_TIME_APP, { $BODY: '"B"', $TIMEOUT: 2000 }),

				function(cb) {
					setTimeout(function() {
						self.write('hanger.js', GOOD_APP, { $BODY: '"C"', $TIMEOUT: 2000 })(cb);
					}, 1000);
				},

				self.waitForSuccess('hanger.js', 'C'),

			]);
		},

		//
		// Started
		//

		startWhileStarted: function(test) {
			var self = this;
			return series(test, [
				self.write('you.js', GOOD_APP, { $BODY: '"m"' }),
				self.start('you.js'),
				self.waitForSuccess('you.js', 'm'),
				self.start('you.js'),
				self.waitForSuccess('you.js', 'm'),
			]);
		},

		stopWhileStarted: function(test) {
			var self = this;
			return series(test, [
				self.write('you.js', GOOD_APP, { $BODY: '"m"' }),
				self.start('you.js'),
				self.waitForSuccess('you.js', 'm'),
				self.stop('you.js'),
				self.waitForFailure('you.js', 'm'),
			]);
		},

		termWhileStarted: function(test) {
			var self = this;
			return series(test, [
				self.write('loo.js', LATE_DEATH, { $BODY: '"m"', $DIE_AFTER: 5000 }),
				self.start('loo.js'),
				self.waitForSuccess('loo.js', 'm'),
				self.delay(7000, self.waitForSuccess('loo.js', 'm')),
			]);
		},

		changeWhileStarted: function(test) {
			var self = this;
			return series(test, [
				self.write('koo.js', GOOD_APP, { $BODY: '"k"' }),
				self.start('koo.js'),
				self.waitForSuccess('koo.js', 'k'),
				self.write('koo.js', GOOD_APP, { $BODY: '"h"' }),
				self.waitForSuccess('koo.js', 'h'),
			]);
		},

		//
		// Faulted
		//

		startWhileFaulted: function(test) {
			var self = this;
			return series(test, [
				self.write('foo.js', BAD_APP),
				self.start('foo.js'),
				self.waitForFailure('foo.js'),
				self.start('foo.js'),
				self.waitForFailure('foo.js'),
			]);
		},

		stopWhileFaulted: function(test) {
			var self = this;
			return series(test, [
				self.write('foo.js', BAD_APP),
				self.start('foo.js'),
				self.waitForFailure('foo.js'),
				self.stop('foo.js'),
				self.write('foo.js', GOOD_APP, { $BODY: '"%"' }),
				self.start('foo.js'),
				self.waitForSuccess('foo.js', '%'),
			]);
		},

		termWhileFaulted: function(test) {
			// this is an invalid state and can't be simulated in black box tests
			test.done();
		},


		changeWhileFaulted: function(test) {
			var self = this;
			return series(test, [
				self.write('foo.js', BAD_APP),
				self.start('foo.js'),
				self.waitForFailure('foo.js'),
				self.write('foo.js', GOOD_APP, { $BODY: '"%"' }),
				self.waitForSuccess('foo.js', '%'),
			]);
		},

		//
		// Restarting: TODO
		//

		//
		// Stopping
		//

		startWhileStopping: function(test) {
			var self = this;
			return series(test, [

			]);
		},

	});
};

exports.unixdomainports = createTests();
