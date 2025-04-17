var http = require('http');
var spinner = require('spinner').createSpinner();

process.chdir(__dirname);

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