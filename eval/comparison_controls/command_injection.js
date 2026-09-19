const childProcess = require('child_process')
const http = require('http')
const url = require('url')

http.createServer(function vulnerableCommand(req, res) {
  const file = url.parse(req.url, true).query.path
  childProcess.execSync(`wc -l ${file}`)
  res.end('done')
})

http.createServer(function safeCommand(req, res) {
  const file = url.parse(req.url, true).query.path
  childProcess.execFileSync('wc', ['-l', file])
  res.end('done')
})
