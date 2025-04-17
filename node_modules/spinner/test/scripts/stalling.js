console.log('starting process.... it will take about 5 seconds');

setTimeout(function() {
	
	var http = require('http');
	http.createServer(function(req, res) {
		res.end('here');
	}).listen(process.env.PORT);

	console.log('listening on port', process.env.PORT);

}, 2000);