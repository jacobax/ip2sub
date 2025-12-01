// ===== 配置区 =====
const CONFIG = {
  SUB_API: '',        // 转换后端
  SUB_CONFIG: '',     // 转换配置
  FILE_NAME: 'CF-Workers-SUB',
  UPDATE_INTERVAL: 6,

  UUID: '',           // vless uuid
  MIMA: '',           // trojan 密码
  HOST_V: '',         // vless host
  HOST_T: '',         // trojan host
  VLESS_PREFIX: '/snippets/ip=',
  TROJAN_PREFIX: '/proxyip=',

  UNI_COUNT: 5,
  DIFF_COUNT: 5,

  API_UNI: '',        // 反代同优选 API
  API_DIFF: '',       // 反代取自 fdip API

  IPS: [              // 固定优选（可留空）
    'cdn.qmqm.cf:443#官方',
    'mfa.gov.ua:443#官方',
  ],

  FDIP: [             // 固定反代（支持 William 域名！）
    'us.proxyip.com:443#US',
  ],

  // ===== 新增：TXT 动态域名规则表（想加多少加多少）=====
  TXT_RULES [
  // 规则格式：{ keywords: ['william'], tld: 'us.ci' }   // 可选 tld，方便以后只匹配特定后缀
  { keywords: ['william'] },                         // 现有 William
  { keywords: ['abc123', 'xyz789'] },                // 假设以后出现的
  // 继续往下加就行……
  ];

  KV_FDIP_KEY: 'FDIP_LIST',   // KV 源反代（支持 William 域名）
};

// ===== 工具函数 =====
const log = (...a) => console.log('[LOG]', ...a);
const err = (...a) => console.error('[ERR]', ...a);

// ---------- 新增：终极 FDIP 解析器 ----------
function isIPv4(s) { return /^(\d+\.){3}\d+$/.test(s) && s.split('.').every(n => +n >= 0 && +n <= 255); }
function isIPv6(s) { return /^([0-9a-fA-F:]+::?)+[0-9a-fA-F]*$/.test(s.replace(/[\[\]]/g, '')); }

async function 解析FDIP(raw) {
  if (!raw) return null;
  let [addr, comment = ''] = raw.split('#');
  addr = addr.trim().toLowerCase();

  // ===== 通用 TXT 动态域名解析（支持配置表里所有关键词）=====
  const matchedRule = TXT_RULES.find(rule => 
    rule.keywords.some(kw => addr.includes(kw))
  );

  if (matchedRule) {
    try {
      const resp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(addr)}&type=TXT`, {
        headers: { 'accept': 'application/dns-json' }
      });
      if (resp.ok) {
        const json = await resp.json();
        const txts = (json.Answer || [])
          .filter(r => r.type === 16)
          .map(r => r.data.replace(/^"|"$/g, ''));

        if (txts.length > 0) {
          const candidates = txts.join('')
            .replace(/\\010/g, ',')
            .replace(/\n/g, ',')
            .split(',')
            .map(s => s.trim())
            .filter(s => s && (isIPv4(s) || isIPv6(s)));

          if (candidates.length > 0) {
            addr = candidates[Math.floor(Math.random() * candidates.length)];
            log(`TXT动态解析成功 → \( {addr} (来自 \){raw})`);
          }
        }
      }
    } catch (e) {
      console.error('TXT动态域名解析失败', addr, e);
      // 解析失败仍然继续用原域名（降级使用）
    }
  }

  // ===== 下面保持原样：.tp 端口解析 + 标准 ip:port 解析 =====
  let host = addr;
  let port = 443;

  if (addr.includes('.tp')) {
    const m = addr.match(/\.tp(\d+)/i);
    if (m) port = parseInt(m[1], 10);
  }
  if (addr.includes(']:')) {
    const parts = addr.split(']:');
    host = parts[0] + ']';
    port = parseInt(parts[1], 10) || 443;
  } else if (addr.includes(':') && !addr.startsWith('[')) {
    const last = addr.lastIndexOf(':');
    host = addr.slice(0, last);
    port = parseInt(addr.slice(last + 1), 10) || 443;
  }

  if (!host || (!isIPv4(host) && !isIPv6(host) && !host.includes('.tp') && !matchedRule)) {
    return null;
  }

  return { ip: host, port: String(port), name: comment.trim() || host };
}

// ---------- 原有工具函数 ----------
const parseLine = (line) => {
  if (!line?.includes(':')) return null;
  const [addr, name = ''] = line.split('#');
  const [ip, port] = addr.split(':');
  const portNum = parseInt(port, 10);
  if (!ip || isNaN(portNum) || portNum < 1 || portNum > 65535) return null;
  return { ip, port: String(portNum), name: name.trim() };
};

const fetchLines = async (url) => {
  if (!url?.trim()) return [];
  try {
    const r = await fetch(url);
    if (!r.ok) return [];
    return r.text().then(t => t.split('\n').map(parseLine).filter(Boolean));
  } catch (e) {
    err(`Fetch失败: ${url}`, e);
    return [];
  }
};

const fetchKvList = async (env, key) => {
  if (!env?.KV) return [];
  try {
    const v = await env.KV.get(key);
    return v ? v.split('\n').map(line => ({ line, ...parseLine(line) })).filter(x => x.ip) : [];
  } catch (e) {
    err(`KV读取失败: ${key}`, e);
    return [];
  }
};

const randomSampleByName = (list, count) => {
  if (count === 'all') return list;
  if (!count || count <= 0) return [];
  const grouped = list.reduce((acc, x) => {
    const key = x.name || 'unknown';
    acc[key] = acc[key] || [];
    acc[key].push(x);
    return acc;
  }, {});
  return Object.values(grouped).flatMap(group =>
    group.length <= count ? group : group.sort(() => 0.5 - Math.random()).slice(0, count)
  );
};

const selectFdip = (name, fdips) => {
  if (!fdips.length) return [null, null];
  const lowerName = name.toLowerCase();
  const exact = fdips.find(f => f.name && lowerName.includes(f.name.toLowerCase()));
  const pick = exact || fdips[Math.floor(Math.random() * fdips.length)];
  return [pick.ip, pick.port];
};

const buildPath = (isTrojan, ip, port, vlessPrefix, trojanPrefix) =>
  encodeURIComponent(`\( {isTrojan ? trojanPrefix : vlessPrefix} \){ip}:${port}`);

const generateNode = (tpl, ip, port, name, pathIp, pathPort, vp, tp) => {
  const isTrojan = tpl.includes('trojan://');
  const encodedName = encodeURIComponent(name || ip);
  const path = buildPath(isTrojan, pathIp, pathPort, vp, tp);
  return tpl
    .replaceAll('[ip]', ip)
    .replaceAll('[port]', port)
    .replaceAll('[path]', path)
    .replaceAll('[name]', encodedName);
};

const processNodes = (lines, tpl, opt) => {
  if (!lines?.length) return [];
  return lines.map(({ ip, port, name }) => {
    let [pathIp, pathPort] = [ip, port];
    if (opt.useForced) [pathIp, pathPort] = [opt.fdipIp, opt.fdipPort];
    else if (opt.useAll || !opt.isUni) {
      const [fdipIp, fdipPort] = selectFdip(name, opt.validFDIP);
      if (fdipIp) [pathIp, pathPort] = [fdipIp, fdipPort];
    }
    return generateNode(tpl, ip, port, name, pathIp, pathPort, opt.vp, opt.tp);
  });
};

// ===== Worker 主体 =====
export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      const sp = url.searchParams;

      const useTrojan = sp.get('trojan') === '1';
      const dyn = {
        uuid: sp.get('uuid') || CONFIG.UUID,
        mima: sp.get('mima') || CONFIG.MIMA,
        hostV: sp.get('hostV') || CONFIG.HOST_V,
        hostT: sp.get('hostT') || CONFIG.HOST_T,
        vp: sp.get('vlessPrefix') || CONFIG.VLESS_PREFIX,
        tp: sp.get('trojanPrefix') || CONFIG.TROJAN_PREFIX,
      };

      const parseCount = (k, d) => {
        const v = sp.get(k);
        if (!v) return d;
        if (v === '0') return 0;
        if (v.toLowerCase() === 'all') return 'all';
        const n = parseInt(v, 10);
        return isNaN(n) ? d : n;
      };
      const uniCount = parseCount('uni_count', CONFIG.UNI_COUNT);
      const diffCount = parseCount('diff_count', CONFIG.DIFF_COUNT);

      const tpl = useTrojan
        ? `trojan://\( {dyn.mima}@[ip]:[port]?security=tls&sni= \){dyn.hostT}&fp=chrome&type=ws&host=${dyn.hostT}&path=[path]#[name]`
        : `vless://\( {dyn.uuid}@[ip]:[port]?path=[path]&security=tls&alpn=h3&encryption=none&host= \){dyn.hostV}&fp=random&type=ws&sni=${dyn.hostV}#[name]`;

      // ===== 终极版 FDIP 处理（支持 URL 参数动态传入）=====
      const fdipParam = sp.get('fdip')?.trim();
      let opt = {
        vp: dyn.vp, tp: dyn.tp,
        validFDIP: [], isUni: false,
        useForced: false, useAll: false,
        fdipIp: null, fdipPort: null
      };

      if (fdipParam === 'all') {
        opt.useAll = true;
      } else if (fdipParam && !fdipParam.includes('#')) {
        // 用户动态传入一个反代地址（支持 William、.tp、ip:port 等）
        const dynamic = await 解析FDIP(fdipParam + '#动态参数');
        if (dynamic) {
          opt.fdipIp = dynamic.ip;
          opt.fdipPort = dynamic.port;
          opt.useForced = true;
          log(`动态反代: \( {opt.fdipIp}: \){opt.fdipPort}`);
        }
      } else if (fdipParam?.includes(':')) {
        // 兼容老格式 ip:port
        const [ip, port] = fdipParam.split(':');
        const p = parseInt(port, 10);
        if (ip && p > 0 && p <= 65535) {
          opt.fdipIp = ip.trim();
          opt.fdipPort = String(p);
          opt.useForced = true;
        }
      }

      // 解析配置 + KV 中的 FDIP（支持 William 域名）
      const rawFDIP = [
        ...CONFIG.FDIP,
        ...(await fetchKvList(env, CONFIG.KV_FDIP_KEY)).map(x => x.line)
      ];
      const validFDIP = [];
      for (const raw of rawFDIP) {
        const parsed = await 解析FDIP(raw);
        if (parsed) validFDIP.push({ line: raw, ...parsed });
      }
      opt.validFDIP = validFDIP;

      // 数据源
      const uniLines = uniCount !== 0 ? await fetchLines(CONFIG.API_UNI) : [];
      const diffLines = diffCount !== 0 ? await fetchLines(CONFIG.API_DIFF) : [];
      const ipsLines = CONFIG.IPS.map(parseLine).filter(Boolean);

      const uniNodes = processNodes(randomSampleByName(uniLines, uniCount), tpl, { ...opt, isUni: true });
      const diffNodes = processNodes(randomSampleByName(diffLines, diffCount), tpl, opt);
      const ipsNodes = processNodes(ipsLines, tpl, opt);

      const allNodes = [...uniNodes, ...ipsNodes, ...diffNodes];
      if (!allNodes.length) return new Response('无可用节点', { status: 404 });

      if ((ipsNodes.length || diffNodes.length || (opt.useAll && uniNodes.length)) &&
          !opt.useForced && !opt.validFDIP.length) {
        return new Response('FDIP 无效或为空', { status: 500 });
      }

      return handleSubscription(req, allNodes.join('\n'), req.url, env);
    } catch (e) {
      err('运行错误', e);
      return new Response('运行错误: ' + (e?.message || String(e)), { status: 500 });
    }
  },
};

// ===== 订阅转换（保持原样）=====
async function handleSubscription(req, data, subUrl, env) {
  const ua = (req.headers.get('User-Agent') || '').toLowerCase();
  const url = new URL(req.url);
  const converter = env?.SUBAPI || CONFIG.SUB_API;
  const cfg = env?.SUBCONFIG || CONFIG.SUB_CONFIG;
  const proto = converter.startsWith('http://') ? 'http' : 'https';
  const host = converter.replace(/^https?:\/\//, '');

  const detectFmt = () => {
    if (url.searchParams.has('b64') || url.searchParams.has('base64')) return 'base64';
    if (/sing(-?box)?/.test(ua) || url.searchParams.has('singbox')) return 'singbox';
    if (/surge/.test(ua) || url.searchParams.has('surge')) return 'surge';
    if (/quantumult/.test(ua) || url.searchParams.has('quanx')) return 'quanx';
    if (/loon/.test(ua) || url.searchParams.has('loon')) return 'loon';
    if (/clash|meta|mihomo/.test(ua) || url.searchParams.has('clash')) return 'clash';
    return 'base64';
  };
  const fmt = detectFmt();

  const uniqLines = [...new Set(data.split('\n').filter(Boolean))].join('\n');
  const base64 = encodeBase64(uniqLines);

  const headers = {
    'content-type': 'text/plain; charset=utf-8',
    'Profile-Update-Interval': String(CONFIG.UPDATE_INTERVAL),
    'Profile-web-page-url': url.origin + url.pathname,
  };
  if (!ua.includes('mozilla')) headers['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(CONFIG.FILE_NAME)}`;

  if (fmt === 'base64') return new Response(base64, { headers });

  const targetMap = { singbox: 'singbox', surge: 'surge&ver=4', quanx: 'quanx&udp=true', loon: 'loon', clash: 'clash' };
  const target = targetMap[fmt] || 'clash';
  const subUrlFull = `\( {proto}:// \){host}/sub?target=\( {target}&url= \){encodeURIComponent(subUrl)}&insert=false&config=${encodeURIComponent(cfg)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;

  try {
    const r = await fetch(subUrlFull);
    if (!r.ok) return new Response(base64, { headers });
    let c = await r.text();
    if (fmt === 'clash') c = clashFix(c);
    return new Response(c, { headers });
  } catch {
    return new Response(base64, { headers });
  }
}

function encodeBase64(str) {
  try { return btoa(str); }
  catch {
    const b = new TextEncoder().encode(str);
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '', i = 0;
    while (i < b.length) {
      const [a = 0, d = 0, e = 0] = [b[i++], b[i++], b[i++]];
      out += c[a >> 2] + c[((a & 3) << 4) | (d >> 4)] + c[((d & 15) << 2) | (e >> 6)] + c[e & 63];
    }
    const pad = 3 - (b.length % 3 || 3);
    return out.slice(0, out.length - pad) + '=='.slice(0, pad);
  }
}

function clashFix(content) {
  if (!content.includes('wireguard')) return content;
  return content
    .split(/\r?\n/)
    .map(line => line.includes('type: wireguard')
      ? line.replace(/, mtu: 1280, udp: true/, ', mtu: 1280, remote-dns-resolve: true, udp: true')
      : line)
    .join('\n')
    .trim();
}
