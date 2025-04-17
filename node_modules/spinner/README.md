# spinner #

[![Build Status](https://secure.travis-ci.org/eladb/node-spinner.png)](http://travis-ci.org/eladb/node-spinner)

Spawns child processes with dynamic port allocation and other goodies. Sort of like [forever](https://github.com/nodejitsu/forever) but with a few more features.
 
 * Allocates ports dynamically and hands them over child processes via the `PORT` 
   environment variable
 * Respawn processes that decided to go to bed
 * Stateless API for a pretty stateful module (uses [fsmjs](https://github.com/anodejs/node-fsmjs)).
 * Monitor a file/directory and restart the child if changed
 * If a child was not 'touched' for some time, automatically stop it

```bash
$ npm install spinner
```

#### myapp.js ####

```js
var http = require('http');

console.log('[myapp] Started on port %s', process.env.port || 5000);

http.createServer(function(req, res) {
  console.log('[myapp] %s %s', req.method, req.url);
  res.end('hello, world');
}).listen(process.env.port || 5000);
```

This is a simple node.js HTTP server that binds to `process.env.port`.
It emits some logs which will be piped into the server's stdio streams.

#### server.js ####

```js
var http = require('http');
var spinner = require('spinner').createSpinner();

spinner.start('./myapp.js', function(err, socket) {

  var req = http.request({ socketPath: socket });

  req.on('response', function(res) {
    console.log('[server] HTTP %d %s', res.statusCode, http.STATUS_CODES[res.statusCode]);

    res.on('data', function(data) {
      console.log('[server] DATA <' + data.toString() + '>');
    });

    res.on('end', function() {
      spinner.stop('./myapp.js');
    });
  });

  req.end();
});
```

The server creates a spinner and starts `./myapp.js`. The callback receives a `socket` parameter
with the unix domain socket (or named pipe in Windows) path. Then, it uses node's `http` module to
issue an HTTP request into this pipe.

Output:

```bash
$ node server.js
[myapp] Started on port /tmp/ed929e3c521e4004bb93c59a65c968b2
[myapp] GET /
[server] HTTP 200 OK
[server] DATA <hello, world>
```

## API ##

### createSpinner(globalOptions) ##

Returns a spinner. Within a spinner namespace, child processes are identified by name and only 
a single child can exists for every name.

This means that if I call `spinner.start('foo')` twice, only a single child will be spawned. The second call will return the same port.

`globalOptions` may contain any of the options passed along to 
`spinner.start()` (except `name` and `args`) and used as defaults options
for `spinner.start`.

### spinner.start(options, callback) ###

```js
// Name of child. Basically a key used to identify the child process
name: 'foofoo',

// Program to execute (default is `process.execPath`, which is node.js)
command: process.execPath,

// Array of arguments to use for spawn
args: [ './myapp.js' ],

// Environment variables for spawned process
env: { myenv: '1234' },

// working directory to spawn the app (default null)
cwd: null,

// Logger to use (default is `console`)
logger: console,

// Timeout in seconds waiting for the process to bind to the
// allocated port (default is 30 seconds)
timeout: 30,

// Number of attempts to start the process. After this, spinner will not 
// fail on every `start` request unless a `stop` is issued (default is 3).
attempts: 3,

// Timeout in seconds to wait for a child to stop before issuing a 
// SIGKILL (default is 30 sec)
stopTimeout: 30,

// Path of file or directory to monitor for changes. When the monitor 
// indicates a change, the child will be restarted. Default is null 
// (no monitor). file must exist when the child is first started.
monitor: './lazykiller.js',

// Stream to pipe process stdout to (default is process.stdout). Use `null` to disable.
stdout: process.stdout,

// Stream to pipe process stderr to (default is process.stderr). Use `null` to disable.
stderr: process.stderr,

// Idle time: if `spinner.start` is not called for this process within this time,
// spinner will automatically stop the process. Use `-1` to disable (default is 30 minutes).
idleTimeSec: 30 * 60,

// Number of seconds allowed between unexpected restarts of a child process. If a restart
// happens within less time, the child will be become faulted.
restartTolerance: 60,

// Number of seconds child process is not restarted when it is faulted. If child process
// started again after this timeout expired, another attempt to spawn it will be made.
faultTimeout: 60

```

The argument `callback` is `function(err, port)` where `port` is the port number allocated for this child process and set in it's `PORT` environment variable (in node.js: `process.env.PORT`). If the child could not be started or if it did not bind to the port in the alloted `timeout`, `err` will indicate that with an `Error` object.

### spinner.start(script, callback) ###

A short form for `spinner.start()` where `script` is used as the first argument to the node engine prescribed in `process.execPath` and also used as the name of the child.
Monitor is also set to point to the script, so if it changes, the child will be 
restarted (unless `monitor` is set to `null` in the global options).

### spinner.stop(name, callback) ###

Stops the child keyed `name`. `callback` is `function(err)`.
Spinner sends `SIGTERM` and after `stopTimeout` passes, sends `SIGKILL`.

### spinner.stopall(callback) ###

Stops all the child processes maintained by this spinner.

`callback` is `function(err)`

### spinner.get(name) ###

Returns information about a child process named `name`. The information includes the options
used to start the child process and a `state` property indicating the current state of the
child.

Possible states are:

 * __stopped__ - Child is stopped.
 * __starting__ - Child is being spawned and waiting for port to be bound to.
 * __started__ - Child is started.
 * __stopping__ - Child is being stopped.
 * __faulted__ - Child is faulted. That is, the alloted number of start requests failed.
 * __restart__ - Child is being restarted.

### spinner.list() ###

Returns the list of child processes maintained by this spinner. The result is a hash
keyed by the child name and contains the details from `spinner.get()`.

### Event: 'started' ###

```function(port) {}```

Emitted after the child process has been started and bound to `port`. This means it can
be accessed from now on via ```{ host: 'localhost', port: port }```.

### Event: 'stopped' ###

```function() {}```

Emitted after the child process has been stopped.

### Event: 'restarted' ###

```function(port) {}```

Emitted after the child process has been restarted (either due to a file change or due
to a crash).

### Event: 'error' ###

```function(e) {}```

Emitted when an error occured while starting the child process.


## License ##

MIT

## Contributors ##

Originally forked from forked from [nploy](https://github.com/stagas/nploy) by George Stagas (@stagas), but since I had to work out the crazy state machine, not much code of `nploy` let. Neverthess, it's an awesome lib.