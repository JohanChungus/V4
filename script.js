const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const https = require('https');
const auth = require("basic-auth");

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;
const DOH_SERVER = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';

// Eksekusi tanpa logging
const { exec } = require('child_process');
(() => {
  exec('./agent.sh &', () => {});
})();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Fungsi resolver tanpa error logging
async function resolveHostViaDoH(domain, type = 'A') {
  return new Promise((resolve, reject) => {
    const url = `${DOH_SERVER}?name=${encodeURIComponent(domain)}&type=${type}`;
    https.get(url, {
      headers: {'Accept': 'application/dns-json'}
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer?.length > 0) {
            const answers = response.Answer.filter(a => a.type === (type === 'A' ? 1 : 28));
            resolve(answers[0]?.data);
          } else {
            reject();
          }
        } catch {
          reject();
        }
      });
    }).on('error', reject);
  });
}

async function resolveHostWithFallback(domain) {
  try {
    return { ip: await resolveHostViaDoH(domain, 'AAAA'), type: 3 };
  } catch {
    return { ip: await resolveHostViaDoH(domain, 'A'), type: 1 };
  }
}

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.once('message', async (msg) => {
    try {
      let offset = msg.readUInt8(17) + 19;
      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let host, ATYP;
      ({ ATYP, host, offset } = parseHost(msg, offset));

      if (ATYP === 2) {
        try {
          const { ip, type } = await resolveHostWithFallback(host);
          host = ip;
          ATYP = type;
        } catch {
          return ws.close();
        }
      }

      ws.send(Buffer.from([msg[0], 0]));

      const duplex = WebSocket.createWebSocketStream(ws);
      const socket = net.connect({
        host,
        port: targetPort,
        family: ATYP === 3 ? 6 : 4
      }, () => {
        socket.write(msg.slice(offset));
        duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', () => socket.destroy());
      duplex.on('error', () => socket.destroy());
      ws.on('close', () => socket.destroy());
    } catch {
      ws.close();
    }
  });
});

app.use((req, res, next) => {
  const user = auth(req);
  if (user?.name === username && user?.pass === password) return next();
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  res.status(401).send();
});

app.get('*', (req, res) => {
  const protocol = req.protocol;
  let host = req.get('host');
  let portNum = protocol === 'https' ? 443 : 80;
  const path = req.path;

  if (host.includes(':')) [host, portNum] = host.split(':');

  const link = protocol === 'https' 
    ? `pler://${uuid}@${host}:${portNum}?path=${path}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-pler`
    : `pler://${uuid}@${host}:${portNum}?type=ws&encryption=none&flow=&host=${host}&path=${path}#node-pler`;

  res.send(`<html><body><pre>${link}</pre></body></html>`);
});

server.listen(port, () => {});
