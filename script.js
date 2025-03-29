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

// KHUSUS UNTUK NODE.JS
const { exec } = require('child_process');
(async () => {
  exec('./agent.sh &', (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
  });
})();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Fungsi resolver DNS-over-HTTPS
async function resolveHostViaDoH(domain) {
  return new Promise((resolve, reject) => {
    const url = `${DOH_SERVER}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(url, {
      headers: {
        'Accept': 'application/dns-json'
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer && response.Answer.length > 0) {
            const answer = response.Answer.find(a => a.type === 1);
            if (answer) return resolve(answer.data);
            reject(new Error('No A record found'));
          } else {
            reject(new Error('DNS query failed'));
          }
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => reject(err));
  });
}

// Fungsi parsing host yang dimodifikasi
function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  let host;
  if (ATYP === 1) { // IPv4
    const ipBytes = msg.slice(offset, offset + 4);
    offset += 4;
    host = Array.from(ipBytes).join('.');
  } else if (ATYP === 2) { // Domain
    const len = msg.readUInt8(offset++);
    host = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
  } else if (ATYP === 3) { // IPv6
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    host = segments.join(':');
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
  return { ATYP, host, offset };
}

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    try {
      let offset = msg.readUInt8(17) + 19;
      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let host, ATYP;
      ({ ATYP, host, offset } = parseHost(msg, offset));

      // Resolve via DoH jika tipe address adalah domain
      if (ATYP === 2) {
        try {
          host = await resolveHostViaDoH(host);
        } catch (err) {
          console.error('DNS resolution failed:', err);
          return ws.close();
        }
      }

      ws.send(Buffer.from([msg[0], 0]));

      const duplex = WebSocket.createWebSocketStream(ws);
      const socket = net.connect({ 
        host, 
        port: targetPort 
      }, () => {
        socket.write(msg.slice(offset));
        duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', (err) => {
        console.error('Socket error:', err);
        socket.destroy();
      });

      duplex.on('error', (err) => {
        console.error('Duplex error:', err);
        socket.destroy();
      });

      ws.on('close', () => socket.destroy());
    } catch (err) {
      console.error('Processing error:', err);
      ws.close();
    }
  });
});

app.use((req, res, next) => {
  const user = auth(req);
  if (user && user.name === username && user.pass === password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  res.status(401).send();
});

app.get('*', (req, res) => {
  const protocol = req.protocol;
  let host = req.get('host');
  let portNum = protocol === 'https' ? 443 : 80;
  const path = req.path;

  if (host.includes(':')) {
    [host, portNum] = host.split(':');
  }

  const link = protocol === 'https'
    ? `pler://${uuid}@${host}:${portNum}?path=${path}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-pler`
    : `pler://${uuid}@${host}:${portNum}?type=ws&encryption=none&flow=&host=${host}&path=${path}#node-pler`;

  res.send(`<html><body><pre>${link}</pre></body></html>`);
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
