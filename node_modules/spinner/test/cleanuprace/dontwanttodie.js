var http = require('http');

http.createServer(function(req, res) {
	process.exit(444);
}).listen(process.env.PORT || 5000);

console.log("can't kill me...");

process.on('SIGTERM', function() {
	console.log('no no no ...');
});

/*
we want that app2 will bind to a port that was previously allocated for app1
the only way for this to happen is:

a: find() -> 7000
b: find() -> 7000
*/