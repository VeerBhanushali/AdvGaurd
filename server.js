const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');

const dev = process.env.NODE_ENV !== 'production';
const hostname = process.env.HOST || '0.0.0.0';
const port = parseInt(process.env.PORT || '3001', 10);
const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = createServer(async (req, res) => {
    // Always overwrite: clients must not be able to inject their own value.
    req.headers['x-advguard-remote-addr'] = req.socket.remoteAddress || '';
    try {
      await handle(req, res, parse(req.url, true));
    } catch (err) {
      console.error('Error handling', req.url, err);
      res.statusCode = 500;
      res.end('Internal Server Error');
    }
  });

  // Slow-loris / idle connection protection.
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 65_000;

  server
    .once('error', (err) => {
      console.error('AdvGuard server error:', err);
      process.exit(1);
    })
    .listen(port, hostname, () => {
      console.log(`> AdvGuard running on http://${hostname}:${port} (DoH endpoint: /dns-query)`);
      if (!process.env.ADMIN_PASSWORD && !dev) {
        console.warn('> WARNING: ADMIN_PASSWORD is not set – the admin dashboard is DISABLED.');
      }
    });
});
