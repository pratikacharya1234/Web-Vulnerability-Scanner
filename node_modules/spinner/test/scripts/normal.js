console.log('starting a');
var http = require('http');
http.createServer(function(req, res) {
	res.end('BBBBBBBBBBBBBB');
}).listen(process.env.PORT, function(err) {
	if (err) return console.error(err);
	return console.info('started on port ' + process.env.PORT);
});
