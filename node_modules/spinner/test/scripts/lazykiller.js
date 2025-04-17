console.log('starting a');
var http = require('http');
http.createServer(function(req, res) {
	res.end('this is a sample app');
}).listen(process.env.PORT, function(err) {
	if (err) return console.error(err);
	return console.info('started on port ' + process.env.PORT);
});

// crash process after 5s
var i = 5;
setInterval(function() {
	if (i == 0) throw new Error();
	console.log('dead in ' + i + 'sec');
	i--;
}, 1000);

