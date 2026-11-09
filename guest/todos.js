// A todos app: HTTP on :3000, rows in Postgres.
// Hand-rolled pg wire protocol — a deny-by-default guest has no network
// to npm install from, which is the whole point.
const net = require('net');
const http = require('http');

function msg(type, body) {
  const len = body.length + 4;
  const head = Buffer.alloc(type ? 5 : 4);
  let o = 0;
  if (type) head.writeUInt8(type.charCodeAt(0), o++);
  head.writeUInt32BE(len, o);
  return Buffer.concat([head, body]);
}
function cstr(s) { return Buffer.concat([Buffer.from(s, 'utf8'), Buffer.alloc(1)]); }

class Pg {
  constructor() { this.sock = null; this.buf = Buffer.alloc(0); }
  connect() {
    return new Promise((resolve, reject) => {
      this.sock = net.connect('/data/run/.s.PGSQL.5432');
      this.sock.on('error', reject);
      this.sock.on('data', (d) => { this.buf = Buffer.concat([this.buf, d]); });
      this.sock.on('connect', () => {
        const startup = Buffer.concat([
          Buffer.from([0, 3, 0, 0]),
          cstr('user'), cstr('postgres'),
          cstr('database'), cstr('postgres'),
          Buffer.alloc(1),
        ]);
        this.sock.write(msg(null, startup));
        this.waitFor('Z').then(resolve).catch(reject);
      });
    });
  }
  async waitFor(target) {
    const deadline = Date.now() + 15000;
    for (;;) {
      let o = 0;
      while (this.buf.length >= o + 5) {
        const type = String.fromCharCode(this.buf[o]);
        const len = this.buf.readUInt32BE(o + 1);
        if (this.buf.length < o + 1 + len) break;
        if (type === 'E') {
          const text = this.buf.subarray(o + 5, o + 1 + len).toString();
          throw new Error('pg error: ' + text.replace(/\0/g, ' '));
        }
        o += 1 + len;
        if (type === target) { this.buf = this.buf.subarray(o); return; }
      }
      if (Date.now() > deadline) throw new Error('timeout waiting for ' + target);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  async query(sql) {
    this.rows = [];
    this.sock.write(msg('Q', cstr(sql)));
    await this.collect();
    return this.rows;
  }
  async collect() {
    const deadline = Date.now() + 15000;
    for (;;) {
      let o = 0;
      while (this.buf.length >= o + 5) {
        const type = String.fromCharCode(this.buf[o]);
        const len = this.buf.readUInt32BE(o + 1);
        if (this.buf.length < o + 1 + len) break;
        const body = this.buf.subarray(o + 5, o + 1 + len);
        if (type === 'D') {
          const count = body.readUInt16BE(0);
          let p = 2; const row = [];
          for (let i = 0; i < count; i++) {
            const size = body.readInt32BE(p); p += 4;
            if (size === -1) { row.push(null); } else { row.push(body.subarray(p, p + size).toString()); p += size; }
          }
          this.rows.push(row);
        }
        if (type === 'E') {
          this.buf = this.buf.subarray(o + 1 + len);
          throw new Error('pg: ' + body.toString().replace(/\0/g, ' '));
        }
        o += 1 + len;
        if (type === 'Z') { this.buf = this.buf.subarray(o); return; }
      }
      if (Date.now() > deadline) throw new Error('query timeout');
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}

(async () => {
  const pg = new Pg();
  await pg.connect();
  console.log('TODOS: connected to postgres');
  await pg.query('CREATE TABLE IF NOT EXISTS todos (id serial primary key, title text not null, done boolean not null default false)');
  console.log('TODOS: schema ready');

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'POST' && req.url === '/todos') {
        let body = '';
        for await (const chunk of req) body += chunk;
        const title = (JSON.parse(body || '{}').title || 'untitled').replace(/'/g, "''");
        await pg.query(`INSERT INTO todos (title) VALUES ('${title}')`);
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ added: title }));
        return;
      }
      if (req.method === 'GET' && req.url === '/todos') {
        const rows = await pg.query('SELECT id, title, done FROM todos ORDER BY id');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(rows.map(([id, title, done]) => ({ id: +id, title, done: done === 't' }))));
        return;
      }
      res.writeHead(404); res.end('no');
    } catch (error) {
      res.writeHead(500); res.end(String(error));
    }
  });
  server.listen(3000, '0.0.0.0', () => console.log('TODOS: listening on 3000'));
})().catch((e) => { console.log('TODOS-FAILED: ' + e.message); });
