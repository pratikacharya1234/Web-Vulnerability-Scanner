var http = require('http');
http.createServer(function(req, res) {
    res.end('normal\n');
}).listen(process.env.PORT || 5000);

console.log('started normal');
