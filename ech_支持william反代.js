// ====================== 配置区 ======================
const CONFIG = {
  TOKEN: 'mima',                              // 留空则不校验
  PROXYIP_KEYWORDS: ['关键词'],             // 支持威廉反代及其它相同处理的反代域名
  CF_FALLBACK_IPS: ['1.proxyip.com', '2.proxyip.com:1234'],  // proxyIP，依次尝试，165行处 .sort(() => Math.random() - 0.5) 控制是否打乱
  TXT_DNS_SERVER: 'https://1.1.1.1/dns-query',
  CACHE_TTL_MS: 5 * 60 * 1000,                 // 5 分钟缓存
  CONNECT_TIMEOUT_MS: 4500,                   // 单个 TCP 连接超时
};

const {
  TOKEN,
  PROXYIP_KEYWORDS,
  CF_FALLBACK_IPS,
  TXT_DNS_SERVER,
  CACHE_TTL_MS,
  CONNECT_TIMEOUT_MS,
} = CONFIG;

const encoder = new TextEncoder();
import { connect } from 'cloudflare:sockets';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// ====================== 缓存 ======================
const resolveCache = new Map(); // lowerKey → {host, port, expireAt}

async function resolveHostPort(raw) {
  const lowerKey = raw.toLowerCase();
  const cached = resolveCache.get(lowerKey);
  if (cached && cached.expireAt > Date.now()) {
    return { host: cached.host, port: cached.port };
  }

  let host = raw.trim();
  let port = 443;

  // Step 1: TXT 解析（支持多个关键词）
  const needTxt = PROXYIP_KEYWORDS.some(k => lowerKey.includes(k));
  if (needTxt) {
    try {
      const resp = await fetch(
        `\( {TXT_DNS_SERVER}?name= \){encodeURIComponent(raw)}&type=TXT`,
        { headers: { accept: 'application/dns-json' } }
      );
      if (resp.ok) {
        const { Answer = [] } = await resp.json();
        const txt = Answer.find(r => r.type === 16)?.data || '';
        if (txt) {
          let clean = txt.replace(/^"|"$/g, ''); // 正确去掉首尾引号
          const ips = clean
            .replace(/\\010/g, ',')
            .replace(/\n/g, ',')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
          if (ips.length) host = ips[Math.floor(Math.random() * ips.length)];
        }
      }
    } catch {
      // 静默失败，继续后面逻辑
    }
  }

  // Step 2: .tp123 端口写法（从右找第一个 .tp）
  const tpMatch = host.match(/\.tp(\d+)$/i);
  if (tpMatch) {
    port = Number(tpMatch[1]);
    host = host.slice(0, tpMatch.index); // 去掉 .tp123
  }
  // Step 3: [ipv6]:port 正确写法
  else if (host.startsWith('[')) {
    const closeBracket = host.indexOf(']');
    if (closeBracket > 1) {
      const maybePort = host.slice(closeBracket + 1);
      if (maybePort.startsWith(':') && maybePort.length > 1) {
        port = Number(maybePort.slice(1)) || 443;
      }
      host = host.slice(1, closeBracket); // 去掉 [] 
    }
  }
  // Step 4: 普通 host:port
  else {
    const lastColon = host.lastIndexOf(':');
    if (lastColon > 0 && host.indexOf(':') === lastColon) { // 确保只有一个 :
      const p = Number(host.slice(lastColon + 1));
      if (p > 0 && p < 65536) {
        port = p;
        host = host.slice(0, lastColon);
      }
    }
  }

  const result = { host, port };
  resolveCache.set(lowerKey, { ...result, expireAt: Date.now() + CACHE_TTL_MS });
  return result;
}

// ====================== 主入口 ======================
export default {
  async fetch(request) {
    try {
      const upgrade = request.headers.get('upgrade');
      if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
        return new URL(request.url).pathname === '/'
          ? new Response('WebSocket Proxy OK', { status: 200 })
          : new Response('Upgrade Required', { status: 426 });
      }

      if (TOKEN && request.headers.get('sec-websocket-protocol') !== TOKEN) {
        return new Response('Forbidden', { status: 403 });
      }

      const { 0: client, 1: server } = new WebSocketPair();
      server.accept();

      handleSession(server).catch(() => safeClose(server));

      const headers = new Headers();
      if (TOKEN) headers.set('Sec-WebSocket-Protocol', TOKEN);

      return new Response(null, {
        status: 101,
        webSocket: client,
        headers,
      });
    } catch (e) {
      return new Response('Internal Error', { status: 500 });
    }
  },
};

// ====================== 会话处理 ======================
async function handleSession(ws) {
  let remoteSocket = null;
  let remoteReader = null;
  let remoteWriter = null;
  let closed = false;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    remoteReader?.cancel?.().catch(() => {});
    remoteWriter?.releaseLock?.();
    remoteSocket?.close?.();
    safeClose(ws);
  };

  const pump = async () => {
    try {
      while (!closed && remoteReader) {
        const { done, value } = await remoteReader.read();
        if (done || ws.readyState !== WS_READY_STATE_OPEN) break;
        if (value?.byteLength) ws.send(value);
      }
    } catch {}
    cleanup();
  };

  const tryConnect = async (target, firstPayload) => {
    const main = await resolveHostPort(target);

    // 随机打乱备用IP顺序（推荐）
    const shuffled = [...CF_FALLBACK_IPS]	//.sort(() => Math.random() - 0.5);
    const fallbacks = await Promise.all(shuffled.map(ip => resolveHostPort(ip + ':443')));

    const candidates = [main, ...fallbacks];

    for (const { host, port } of candidates) {
      if (closed) return;

      try {
        const socket = connect({ hostname: host, port });
        // 增加超时
        const opened = await Promise.race([
          socket.opened,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('connect timeout')), CONNECT_TIMEOUT_MS)
          ),
        ]);

        remoteSocket = socket;
        remoteWriter = remoteSocket.writable.getWriter();
        remoteReader = remoteSocket.readable.getReader();

        if (firstPayload) await remoteWriter.write(encoder.encode(firstPayload));
        ws.send('CONNECTED');
        pump();
        return;
      } catch (err) {
        // 只有 CF 自己的错误才继续尝试下一个
        if (!/cloudflare|proxy|cannot connect/i.test(err?.message ?? '')) {
          throw err;
        }
      }
    }
    throw new Error('All attempts failed');
  };

  ws.addEventListener('message', async (e) => {
    if (closed) return;
    try {
      const data = e.data;

      if (typeof data === 'string') {
        if (data.startsWith('CONNECT:')) {
          const sep = data.indexOf('|', 8);
          const target = data.slice(8, sep < 0 ? undefined : sep);
          const payload = sep < 0 ? '' : data.slice(sep + 1);
          await tryConnect(target, payload);
        } else if (data.startsWith('DATA:') && remoteWriter) {
          await remoteWriter.write(encoder.encode(data.slice(5)));
        } else if (data === 'CLOSE') {
          cleanup();
        }
      } else if (data instanceof ArrayBuffer && remoteWriter) {
        await remoteWriter.write(new Uint8Array(data));
      }
    } catch (err) {
      try { ws.send('ERROR:' + err.message); } catch {}
      cleanup();
    }
  });

  ws.addEventListener('close', cleanup);
  ws.addEventListener('error', cleanup);
}

function safeClose(ws) {
  try {
    if ([WS_READY_STATE_OPEN, WS_READY_STATE_CLOSING].includes(ws.readyState)) {
      ws.close(1000);
    }
  } catch {}
}