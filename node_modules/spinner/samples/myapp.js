var http = require('http');

console.log('[myapp] Started on port %s', process.env.port || 5000);

http.createServer(function(req, res) {
  console.log('[myapp] %s %s', req.method, req.url);
  res.end('hello, world');
}).listen(process.env.port || 5000);
