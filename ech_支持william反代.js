// =======================
// 全局配置（可自由修改）
// =======================

const TOKEN = "whmn";	// WebSocket 密码（可为空）

const CF_FALLBACK_IPS = ["tw.william.us.ci"];	// 反代IP/域名

const CUSTOM_KEYWORDS = [
    ".william"	// 反代域名关键词，实现威廉反代域名及其它经过相同处理的反代域名的支持
];

const DNS_ENDPOINT = "https://1.1.1.1/dns-query";	// DNS TXT 查询接口（Cloudflare DoH）


// =======================
// 工具：TXT 查询函数
// =======================
async function queryTXTRecords(domain) {
    try {
        const url = `${DNS_ENDPOINT}?name=${domain}&type=TXT`;

        const response = await fetch(url, {
            headers: { "Accept": "application/dns-json" }
        });

        if (!response.ok) return null;

        const data = await response.json();

        const txtRecords = (data.Answer || [])
            .filter(r => r.type === 16)
            .map(r => r.data);

        if (txtRecords.length === 0) return null;

        let txt = txtRecords[0];

        // 去引号
        if (txt.startsWith('"') && txt.endsWith('"')) {
            txt = txt.slice(1, -1);
        }

        const items = txt
            .replace(/\\010/g, ",")
            .replace(/\n/g, ",")
            .split(",")
            .map(s => s.trim())
            .filter(Boolean);

        if (items.length === 0) return null;

        return items[Math.floor(Math.random() * items.length)];

    } catch (err) {
        console.error("TXT 解析失败:", err);
        return null;
    }
}


// =======================
// 工具：解析 IP + 端口
// =======================
async function 解析地址端口(proxyIP) {
    let addr = proxyIP;
    let port = 443;
    const lower = proxyIP.toLowerCase();

    // 关键词匹配 → 执行 TXT 查询
    for (const kw of CUSTOM_KEYWORDS) {
        if (kw && lower.includes(kw.toLowerCase())) {
            const txt = await queryTXTRecords(proxyIP);
            if (txt) addr = txt;
            break;
        }
    }

    // 特殊端口：.tp1234
    if (lower.includes(".tp")) {
        const m = lower.match(/\.tp(\d+)/);
        if (m) port = parseInt(m[1], 10);
        return [addr, port];
    }

    // IPv6 格式：[xxxx]:1234
    if (addr.includes("]:")) {
        const index = addr.lastIndexOf("]:");
        const host = addr.slice(0, index + 1);
        const p = parseInt(addr.slice(index + 2), 10);
        return [host, p || port];
    }

    // 普通 host:port
    if (addr.includes(":") && !addr.startsWith("[")) {
        const i = addr.lastIndexOf(":");
        const host = addr.slice(0, i);
        const p = parseInt(addr.slice(i + 1), 10);
        if (!isNaN(p)) return [host, p];
    }

    return [addr, port];
}


// ========================================
// 以下为完整 WebSocket 代理代码
// ========================================

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const encoder = new TextEncoder();

import { connect } from "cloudflare:sockets";

export default {
    async fetch(request, env, ctx) {
        try {
            const upgrade = request.headers.get("Upgrade");
            if (!upgrade || upgrade.toLowerCase() !== "websocket") {
                return new URL(request.url).pathname === "/"
                    ? new Response("WebSocket Proxy Server", { status: 200 })
                    : new Response("Expected WebSocket", { status: 426 });
            }

            // 密码验证
            if (TOKEN && request.headers.get("Sec-WebSocket-Protocol") !== TOKEN) {
                return new Response("Unauthorized", { status: 401 });
            }

            const [client, server] = Object.values(new WebSocketPair());
            server.accept();

            handleSession(server).catch(() => safeCloseWebSocket(server));

            const res = { status: 101, webSocket: client };
            if (TOKEN) res.headers = { "Sec-WebSocket-Protocol": TOKEN };
            return new Response(null, res);

        } catch (err) {
            return new Response(err.stack || err, { status: 500 });
        }
    }
};


async function handleSession(ws) {
    let remoteSocket, remoteWriter, remoteReader;
    let closed = false;

    const cleanup = () => {
        if (closed) return;
        closed = true;

        try { remoteWriter?.releaseLock(); } catch {}
        try { remoteReader?.releaseLock(); } catch {}
        try { remoteSocket?.close(); } catch {}

        remoteWriter = remoteReader = remoteSocket = null;
        safeCloseWebSocket(ws);
    };

    const pump = async () => {
        try {
            while (!closed && remoteReader) {
                const { done, value } = await remoteReader.read();
                if (done) break;
                if (ws.readyState !== WS_READY_STATE_OPEN) break;
                if (value?.byteLength > 0) ws.send(value);
            }
        } catch {}

        if (!closed) {
            try { ws.send("CLOSE"); } catch {}
            cleanup();
        }
    };

    const isCFErr = err => {
        const m = err?.message?.toLowerCase() || "";
        return (
            m.includes("proxy request") ||
            m.includes("cannot connect") ||
            m.includes("cloudflare")
        );
    };

    const parseAddress = addr => {
        if (addr[0] === "[") {
            const end = addr.indexOf("]");
            return {
                host: addr.substring(1, end),
                port: parseInt(addr.substring(end + 2), 10)
            };
        }
        const sep = addr.lastIndexOf(":");
        return {
            host: addr.substring(0, sep),
            port: parseInt(addr.substring(sep + 1), 10)
        };
    };

    // ——————————————————————————
    // Connect Remote（含 fallback IP）
    // ——————————————————————————
    const connectRemote = async (targetAddr, firstFrame) => {
        // 先异步解析地址+端口
        const [parsedHost, parsedPort] = await 解析地址端口(targetAddr);

        const attempts = [parsedHost, ...CF_FALLBACK_IPS];

        for (let i = 0; i < attempts.length; i++) {
            try {
                remoteSocket = connect({
                    hostname: attempts[i],
                    port: parsedPort
                });

                if (remoteSocket.opened) await remoteSocket.opened;

                remoteWriter = remoteSocket.writable.getWriter();
                remoteReader = remoteSocket.readable.getReader();

                if (firstFrame) {
                    await remoteWriter.write(encoder.encode(firstFrame));
                }

                ws.send("CONNECTED");
                pump();
                return;

            } catch (err) {
                try { remoteWriter?.releaseLock(); } catch {}
                try { remoteReader?.releaseLock(); } catch {}
                try { remoteSocket?.close(); } catch {}

                remoteWriter = remoteReader = remoteSocket = null;

                if (!isCFErr(err) || i === attempts.length - 1) {
                    throw err;
                }
            }
        }
    };

    // ——————————————————————————
    // WebSocket 事件处理
    // ——————————————————————————
    ws.addEventListener("message", async evt => {
        if (closed) return;

        try {
            const data = evt.data;

            if (typeof data === "string") {
                if (data.startsWith("CONNECT:")) {
                    const sep = data.indexOf("|", 8);
                    const target = data.substring(8, sep);
                    const payload = data.substring(sep + 1);

                    await connectRemote(target, payload);
                }
                else if (data.startsWith("DATA:")) {
                    if (remoteWriter) {
                        await remoteWriter.write(encoder.encode(data.substring(5)));
                    }
                }
                else if (data === "CLOSE") {
                    cleanup();
                }
            } else if (data instanceof ArrayBuffer && remoteWriter) {
                await remoteWriter.write(new Uint8Array(data));
            }

        } catch (err) {
            try { ws.send("ERROR:" + err.message); } catch {}
            cleanup();
        }
    });

    ws.addEventListener("close", cleanup);
    ws.addEventListener("error", cleanup);
}


// =======================
// WebSocket 安全关闭
// =======================
function safeCloseWebSocket(ws) {
    try {
        if (
            ws.readyState === WS_READY_STATE_OPEN ||
            ws.readyState === WS_READY_STATE_CLOSING
        ) {
            ws.close(1000, "Server closed");
        }
    } catch {}
}