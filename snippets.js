import { connect } from 'cloudflare:sockets';

let fdIP = 'proxyip.example.com!txt';
let yourUUID = '495c7195-85b8-498a-bf20-2ea9ce9175b5';

let 缓存反代IP = null;
let 缓存反代解析数组 = null;

const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^\[?([a-fA-F0-9:]+)\]?$/;
const EMPTY_BYTES = new Uint8Array(0);
const DEC = new TextDecoder();

const enc = s => new TextEncoder().encode(s);
const cat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); a.reduce((o, x) => (r.set(x, o), o + x.length), 0); return r; };
const u16 = (b, o) => b[o] << 8 | b[o + 1];
const u32 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
const rng = n => crypto.getRandomValues(new Uint8Array(n));
const rng16 = () => u16(rng(2), 0);
const rng32 = () => u32(rng(4), 0);
const ipB = ip => new Uint8Array(ip.split('.').map(Number));
const cksum = (d, o, n) => { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += u16(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; };
const MSS = 1400;

function formatIdentifier(arr, offset = 0) {
    const hex = Array.from(arr.slice(offset, offset + 16)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        return { earlyData: Uint8Array.from(binaryString, c => c.charCodeAt(0)).buffer, error: null };
    } catch (error) { return { error }; }
}

function closeSocketQuietly(socket) {
    try {
        if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CLOSING) socket.close();
        if (socket?.close) socket.close(); 
    } catch (error) {}
}

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();

    if (proxyStr.startsWith('sstp://')) {
        try {
            const url = new URL(proxyStr);
            return { type: 'sstp', host: url.hostname, port: parseInt(url.port) || 443, username: url.username ? decodeURIComponent(url.username) : 'vpn', password: url.password ? decodeURIComponent(url.password) : 'vpn' };
        } catch (e) { return null; }
    }
    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        try {
            const url = new URL(proxyStr.replace(/^socks:\/\//, 'socks5://'));
            return { type: 'socks5', host: url.hostname, port: parseInt(url.port) || 1080, username: url.username ? decodeURIComponent(url.username) : '', password: url.password ? decodeURIComponent(url.password) : '' };
        } catch (e) { return null; }
    }
    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const isHttps = proxyStr.startsWith('https://');
            const url = new URL(proxyStr);
            return { type: isHttps ? 'https' : 'http', host: url.hostname, port: parseInt(url.port) || (isHttps ? 443 : 80), username: url.username ? decodeURIComponent(url.username) : '', password: url.password ? decodeURIComponent(url.password) : '' };
        } catch (e) { return null; }
    }

    const ipv6Match = proxyStr.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (ipv6Match) {
        const port = parseInt(ipv6Match[2], 10);
        return { type: 'direct', host: ipv6Match[1], port: (!isNaN(port) && port > 0) ? port : 443 };
    }

    const lastColonIndex = proxyStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = proxyStr.substring(0, lastColonIndex);
        const port = parseInt(proxyStr.substring(lastColonIndex + 1), 10);
        if (!isNaN(port) && port > 0 && port <= 65535) return { type: 'direct', host, port };
    }
    return { type: 'direct', host: proxyStr, port: 443 };
}

async function DoH查询(域名, 记录类型) {
    const fetchDns = async (dohUrl) => {
        try {
            const response = await fetch(`${dohUrl}?name=${域名}&type=${记录类型}`, { headers: { 'Accept': 'application/dns-json' } });
            if (response.ok) return (await response.json()).Answer || [];
        } catch (error) {}
        return null;
    };
    return (await fetchDns('https://1.1.1.1/dns-query')) || (await fetchDns('https://dns.google/dns-query')) || [];
}

function 解析地址端口字符串(str) {
    let addr = str, port = 443;
    const match = str.match(/^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/);
    if (match) { addr = match[1] || match[2]; port = match[3] ? parseInt(match[3], 10) : 443; }
    return [addr, port];
}

async function 解析地址端口(fdIPStr, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
    const rawFdIP = fdIPStr.trim();
    if (缓存反代IP === rawFdIP && 缓存反代解析数组) return 缓存反代解析数组;

    const lowerFdIP = rawFdIP.toLowerCase();
    const isTxtMode = lowerFdIP.endsWith('!txt');
    const targetDomain = isTxtMode ? rawFdIP.slice(0, -4).trim() : rawFdIP;
    let 所有反代数组 = [];

    if (isTxtMode) {
        const txtRecords = await DoH查询(targetDomain, 'TXT');
        const txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
        if (txtData.length > 0) {
            let data = txtData[0].replace(/^"|"$/g, '');
            const prefixes = data.replace(/\\010|\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
            所有反代数组 = prefixes.map(解析地址端口字符串);
        }
    } else {
        let [地址, 端口] = 解析地址端口字符串(targetDomain);
        const tpMatch = targetDomain.match(/\.tp(\d+)/);
        if (tpMatch) 端口 = parseInt(tpMatch[1], 10);

        if (!IPV4_REGEX.test(地址) && !IPV6_REGEX.test(地址)) {
            const [aRecords, aaaaRecords] = await Promise.all([ DoH查询(地址, 'A'), DoH查询(地址, 'AAAA') ]);
            const ipAddresses = [...(aRecords.filter(r => r.type === 1).map(r => r.data)), ...(aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`))];
            所有反代数组 = ipAddresses.length > 0 ? ipAddresses.map(ip => [ip, 端口]) : [[地址, 端口]];
        } else {
            所有反代数组 = [[地址, 端口]];
        }
    }

    const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
    let 随机种子 = [...(目标根域名 + UUID)].reduce((acc, char) => acc + char.charCodeAt(0), 0);

    缓存反代解析数组 = [...所有反代数组.sort((a, b) => a[0].localeCompare(b[0]))].sort(() => {
        随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff;
        return (随机种子 / 0x7fffffff) - 0.5;
    }).slice(0, 8);
    
    缓存反代IP = rawFdIP;
    return 缓存反代解析数组;
}

const createSstp = (username, password) => {
  let buf = EMPTY_BYTES, pppId = 1, sock, rd, wr, host, rb = new ArrayBuffer(65536);
  const readBytes = async n => {
    if (buf.length >= n) { const r = buf.subarray(0, n); buf = buf.subarray(n); return r; }
    const saved = buf.length > 0 ? new Uint8Array(buf) : null, need = n - buf.length;
    const { value, done } = await rd.readAtLeast(need, new Uint8Array(rb, 0, 65536));
    if (done) throw 0; rb = value.buffer;
    if (saved) { const t = cat(saved, value); buf = t.subarray(n); return t.subarray(0, n); }
    buf = value.subarray(n); return value.subarray(0, n);
  };
  const readLine = async () => {
    for (;;) {
      const i = buf.indexOf(10);
      if (i >= 0) { let l = DEC.decode(buf.subarray(0, i)); buf = buf.subarray(i + 1); return l.replace(/\r$/, ''); }
      const saved = buf.length > 0 ? new Uint8Array(buf) : null;
      const { value, done } = await rd.readAtLeast(1, new Uint8Array(rb, 0, 65536));
      if (done) throw 0; rb = value.buffer; buf = saved ? cat(saved, value) : value;
    }
  };
  const readPkt = async (ms = 10000) => {
    let t; const to = new Promise((_, r) => { t = setTimeout(() => r('T'), ms); });
    try { const h = await Promise.race([readBytes(4), to]); clearTimeout(t); const len = u16(h, 2) & 0xFFF;
      return { ctrl: (h[1] & 1) !== 0, body: len > 4 ? await readBytes(len - 4) : EMPTY_BYTES }; } catch (e) { clearTimeout(t); throw e; }
  };
  const sstpData = f => { const n = 6 + f.length, p = new Uint8Array(n); p.set([0x10, 0, ((n >> 8) & 0xF) | 0x80, n & 0xFF, 0xFF, 0x03]); p.set(f, 6); return p; };
  const sstpCtrl = (mt, attrs = []) => {
    const al = attrs.reduce((s, a) => s + 4 + a.data.length, 0), p = new Uint8Array(8 + al), v = new DataView(p.buffer);
    p[0] = 0x10; p[1] = 0x01; v.setUint16(2, (8 + al) | 0x8000); v.setUint16(4, mt); v.setUint16(6, attrs.length);
    attrs.reduce((o, a) => (p[o + 1] = a.id, v.setUint16(o + 2, 4 + a.data.length), p.set(a.data, o + 4), o + 4 + a.data.length), 8);
    return p;
  };
  const ppp = (proto, code, id, opts = []) => {
    const ol = opts.reduce((s, o) => s + 2 + o.data.length, 0), f = new Uint8Array(6 + ol), v = new DataView(f.buffer);
    v.setUint16(0, proto); f[2] = code; f[3] = id; v.setUint16(4, 4 + ol);
    opts.reduce((o, x) => (f[o] = x.type, f[o + 1] = 2 + x.data.length, f.set(x.data, o + 2), o + 2 + x.data.length), 6);
    return f;
  };
  const pap = id => { const ul = username.length, pl = password.length, tl = 6 + ul + pl, f = new Uint8Array(2 + tl), v = new DataView(f.buffer);
    v.setUint16(0, 0xc023); f[2] = 1; f[3] = id; v.setUint16(4, tl); f[6] = ul; f.set(enc(username), 7); f[7 + ul] = pl; f.set(enc(password), 8 + ul); return f; };
  const parsePPP = d => { let o = d.length >= 2 && d[0] === 0xFF && d[1] === 0x03 ? 2 : 0; if (d.length - o < 4) return null;
    const p = u16(d, o); return p === 0x0021 ? { protocol: p, ip: d.subarray(o + 2) } : d.length - o >= 6 ? { protocol: p, code: d[o + 2], id: d[o + 3], payload: d.subarray(o + 6), raw: d.subarray(o) } : null; };
  const parseOpts = d => { const r = []; for (let i = 0; i + 2 <= d.length;) { const t = d[i], l = d[i + 1]; if (l < 2 || i + l > d.length) break; r.push({ type: t, data: d.subarray(i + 2, i + l) }); i += l; } return r; };
  const connect_ = async (h, p) => { sock = connect({ hostname: h, port: p }, { secureTransport: 'on' }); await sock.opened; rd = sock.readable.getReader({ mode: 'byob' }); wr = sock.writable.getWriter(); host = h; };
  const establish = async () => {
    const http = enc(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`);
    const pa = new Uint8Array(2); new DataView(pa.buffer).setUint16(0, 1); const mru = new Uint8Array(2); new DataView(mru.buffer).setUint16(0, 1500);
    await wr.write(cat(http, sstpCtrl(0x0001, [{ id: 1, data: pa }]), sstpData(ppp(0xc021, 1, pppId++, [{ type: 1, data: mru }]))));
    const st = await readLine(); while ((await readLine()) !== ''); if (!st.includes('200')) throw 0;
    let sa = false, ld = false, auth = false, done = false, myIp = null;
    for (let r = 0; r < 25 && !done; r++) {
      const pk = await readPkt(); if (pk.ctrl) { if (!sa && pk.body.length >= 2 && u16(pk.body, 0) === 2) sa = true; continue; }
      const pp = parsePPP(pk.body); if (!pp) continue;
      if (pp.protocol === 0xc021) {
        if (pp.code === 1) { const a = new Uint8Array(pp.raw); a[2] = 2; await wr.write(ld && !auth ? cat(sstpData(a), sstpData(pap(pppId++))) : sstpData(a)); if (ld) auth = true; } 
        else if (pp.code === 2) { ld = true; if (!auth) { await wr.write(sstpData(pap(pppId++))); auth = true; } }
      } else if (pp.protocol === 0xc023 && pp.code === 2) await wr.write(sstpData(ppp(0x8021, 1, pppId++, [{ type: 3, data: new Uint8Array(4) }])));
      else if (pp.protocol === 0x8021) {
        if (pp.code === 1) { const a = new Uint8Array(pp.raw); a[2] = 2; await wr.write(sstpData(a)); }
        else if (pp.code === 3) { const o = parseOpts(pp.payload).find(x => x.type === 3); if (o) { myIp = [...o.data].join('.'); await wr.write(sstpData(ppp(0x8021, 1, pppId++, [{ type: 3, data: o.data }]))); } }
        else if (pp.code === 2) { const o = parseOpts(pp.payload).find(x => x.type === 3); if (o) myIp = [...o.data].join('.'); done = true; }
      }
    }
    if (!myIp) throw 0; return myIp;
  };
  const close = () => { [rd, wr, sock].forEach(x => { try { x?.cancel?.() ?? x?.close?.(); } catch {} }); };
  return { connect: connect_, establish, readPkt, parsePPP, get buf() { return buf; }, get wr() { return wr; }, close };
};

const createTcp = (sstp, srcIp, dstIp, dstPort) => {
  const srcPort = 10000 + (rng16() % 50000), srcB = ipB(srcIp), dstB = ipB(dstIp);
  let seq = rng32(), ack = 0;
  const ipTpl = new Uint8Array(20); ipTpl.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); ipTpl.set(srcB, 12); ipTpl.set(dstB, 16);
  const pseudo = new Uint8Array(1432); pseudo.set(srcB); pseudo.set(dstB, 4); pseudo[9] = 6;
  const frame = (flags, data = EMPTY_BYTES) => {
    const pl = data.length, tl = 20 + pl, il = 20 + tl, st = 8 + il, f = new Uint8Array(st), v = new DataView(f.buffer);
    f.set([0x10, 0, ((st >> 8) & 0xF) | 0x80, st & 0xFF, 0xFF, 0x03, 0, 0x21]); f.set(ipTpl, 8);
    v.setUint16(10, il); v.setUint16(12, rng16()); v.setUint16(18, cksum(f, 8, 20));
    v.setUint16(28, srcPort); v.setUint16(30, dstPort); v.setUint32(32, seq); v.setUint32(36, ack);
    f[40] = 0x50; f[41] = flags; v.setUint16(42, 65535); if (pl) f.set(data, 48);
    pseudo[10] = tl >> 8; pseudo[11] = tl & 0xFF; pseudo.set(f.subarray(28, 28 + tl), 12);
    v.setUint16(44, cksum(pseudo, 0, 12 + tl)); return f;
  };
  const match = ip => { if (ip.length < 40 || ip[9] !== 6) return null; const ihl = (ip[0] & 0xF) * 4;
    if (u16(ip, ihl) !== dstPort || u16(ip, ihl + 2) !== srcPort) return null;
    return { flags: ip[ihl + 13], seq: u32(ip, ihl + 4), off: ihl + ((ip[ihl + 12] >> 4) & 0xF) * 4 }; };
  const handshake = async () => {
    await sstp.wr.write(frame(0x02)); seq++;
    for (let i = 0; i < 30; i++) { const pk = await sstp.readPkt(); if (pk.ctrl) continue;
      const pp = sstp.parsePPP(pk.body); if (!pp || pp.protocol !== 0x0021) continue;
      const m = match(pp.ip); if (!m || (m.flags & 0x12) !== 0x12) continue;
      ack = (m.seq + 1) >>> 0; sstp.wr.write(frame(0x10)); return true; }
    throw 0;
  };
  return { frame, match, handshake, get seq() { return seq; }, set seq(v) { seq = v; }, get ack() { return ack; }, set ack(v) { ack = v; } };
};

const sstpConn = async ({ host, port, username, password }, ipP, targetPort) => {
  const sstp = createSstp(username, password), close = () => sstp.close();
  try {
    await sstp.connect(host, port);
    const [myIp, targetIp] = await Promise.all([sstp.establish(), ipP]); if (!targetIp) { close(); return null; }
    const tcp = createTcp(sstp, myIp, targetIp, targetPort); await tcp.handshake();
    let ctrl = null;
    const readable = new ReadableStream({ start: c => { ctrl = c; }, cancel: close });
    (async () => {
      try { let pend = [], pLen = 0;
        const flush = () => { if (!pLen) return; ctrl.enqueue(pend.length === 1 ? pend[0] : cat(...pend)); pend = []; pLen = 0; sstp.wr.write(tcp.frame(0x10)).catch(() => {}); };
        for (;;) { const pk = await sstp.readPkt(60000); if (pk.ctrl) continue;
          const pp = sstp.parsePPP(pk.body); if (!pp || pp.protocol !== 0x0021) continue;
          const m = tcp.match(pp.ip); if (!m) continue;
          if (m.off < pp.ip.length) { const d = pp.ip.subarray(m.off); if (d.length) { tcp.ack = (m.seq + d.length) >>> 0; pend.push(new Uint8Array(d)); pLen += d.length; } }
          if (m.flags & 0x01) { flush(); tcp.ack = (tcp.ack + 1) >>> 0; sstp.wr.write(tcp.frame(0x11)).catch(() => {}); ctrl.close(); return; }
          if (sstp.buf.length < 4 || pLen >= 32768) flush();
        }
      } catch { try { ctrl.close(); } catch {} }
    })();
    const writable = new WritableStream({
      async write(chunk) { const d = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        if (d.length <= MSS) { await sstp.wr.write(tcp.frame(0x18, d)); tcp.seq = (tcp.seq + d.length) >>> 0; return; }
        const frames = []; for (let o = 0; o < d.length; o += MSS) { const seg = d.subarray(o, Math.min(o + MSS, d.length)); frames.push(tcp.frame(0x18, seg)); tcp.seq = (tcp.seq + seg.length) >>> 0; }
        await sstp.wr.write(cat(...frames));
      }, close: () => sstp.wr.write(tcp.frame(0x11)).catch(() => {}), abort: close
    });
    return { readable, writable, close };
  } catch { close(); return null; }
};

async function connect2Socks5({ host, port, username, password }, targetHost, targetPort, initialData) {
    let socket;
    try {
        socket = connect({ hostname: host, port });
        const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
        const authMethods = (username && password) ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        const methodResp = await reader.read();
        
        if (methodResp.done || methodResp.value.byteLength < 2) throw new Error('S5 method failed');
        const selectedMethod = new Uint8Array(methodResp.value)[1];
        
        if (selectedMethod === 0x02) {
            const userBytes = enc(username), passBytes = enc(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; authPacket[1] = userBytes.length; authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length; authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResp = await reader.read();
            if (authResp.done || new Uint8Array(authResp.value)[1] !== 0x00) throw new Error('S5 auth failed');
        } else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth: ${selectedMethod}`);

        const hostBytes = enc(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket.set([0x05, 0x01, 0x00, 0x03, hostBytes.length]);
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        
        await writer.write(connectPacket);
        const connResp = await reader.read();
        if (connResp.done || new Uint8Array(connResp.value)[1] !== 0x00) throw new Error('S5 conn failed');

        if (initialData?.byteLength > 0) await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (e) { closeSocketQuietly(socket); throw e; }
}

async function connect2Http({ type, host, port, username, password }, targetHost, targetPort, initialData) {
    let socket;
    try {
        socket = connect({ hostname: host, port }, type === 'https' ? { secureTransport: 'on', allowHalfOpen: false } : {});
        const writer = socket.writable.getWriter(), reader = socket.readable.getReader();

        let req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
        if (username && password) req += `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`;
        req += `User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        
        await writer.write(enc(req));
        
        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, startTime = Date.now();
        while (headerEndIndex === -1 && responseBuffer.length < 8192) {
            if (Date.now() - startTime > 10000) throw new Error('Timeout');
            const { done, value } = await reader.read();
            if (done) throw new Error('Closed before HTTP resp');

            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer); newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 13 && responseBuffer[i+1] === 10 && responseBuffer[i+2] === 13 && responseBuffer[i+3] === 10) {
                    headerEndIndex = i + 4; break;
                }
            }
        }
        if (headerEndIndex === -1) throw new Error('Invalid HTTP resp');
        const statusMatch = DEC.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch || parseInt(statusMatch[1]) < 200 || parseInt(statusMatch[1]) >= 300) throw new Error(`Conn failed`);

        if (initialData?.byteLength > 0) await writer.write(initialData);
        writer.releaseLock(); reader.releaseLock();
        return socket;
    } catch (e) { closeSocketQuietly(socket); throw e; }
}

async function connect2Sstp(proxyConfig, targetHost, targetPort, initialData) {
    let targetIp = targetHost;
    if (!IPV4_REGEX.test(targetIp)) {
        const aRecords = await DoH查询(targetHost, 'A');
        const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
        if (ipv4List.length > 0) targetIp = ipv4List[0];
        else throw new Error('SSTP requires IPv4 target');
    }

    const sock = await sstpConn(proxyConfig, Promise.resolve(targetIp), targetPort);
    if (!sock) throw new Error('SSTP Conn Failed');

    if (initialData?.byteLength > 0) {
        const writer = sock.writable.getWriter();
        await writer.write(initialData);
        writer.releaseLock();
    }
    return sock;
}

function parseWsPacketHeader(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: 'Invalid uuid' };
    
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    if (cmd !== 1 && cmd !== 2) return { hasError: true, message: 'Invalid cmd' };
    
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
    const addressType = new Uint8Array(chunk.slice(portIdx + 2, addrValIdx))[0];

    switch (addressType) {
        case 1: addrLen = 4; hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); break;
        case 2: addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; hostname = DEC.decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); break;
        case 3: addrLen = 16; const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); hostname = Array.from({ length: 8 }, (_, i) => ipv6View.getUint16(i * 2).toString(16)).join(':'); break;
        default: return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    
    if (!hostname) return { hasError: true, message: 'Invalid address' };
    return { hasError: false, addressType, port, hostname, isUDP: cmd === 2, rawIndex: addrValIdx + addrLen, version };
}

function makeReadableStream(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', e => { if (!cancelled) controller.enqueue(e.data); });
            socket.addEventListener('close', () => { if (!cancelled) { closeSocketQuietly(socket); controller.close(); } });
            socket.addEventListener('error', err => controller.error(err));
            
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { cancelled = true; closeSocketQuietly(socket); }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasData = true;
            if (webSocket.readyState !== WebSocket.OPEN) controller.error('ws not open');
            if (header) {
                const response = new Uint8Array(header.length + chunk.byteLength);
                response.set(header, 0); response.set(chunk, header.length);
                webSocket.send(response.buffer);
                header = null;
            } else { webSocket.send(chunk); }
        }, abort() {}
    })).catch(() => closeSocketQuietly(webSocket));
    if (!hasData && retryFunc) await retryFunc();
}

async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper, customFdIP) {
    const connectDirect = async (address, port, data) => {
        const remoteSock = connect({ hostname: address, port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    };

    let currentFdIP = customFdIP || fdIP;
    let proxyConfig = currentFdIP ? parseProxyAddress(currentFdIP) : null;
    let shouldUseProxy = false;

    if (!proxyConfig) proxyConfig = { type: 'direct', host: fdIP, port: 443 };
    if (proxyConfig.type === 'direct' && currentFdIP) {
        try {
            const resolvedList = await 解析地址端口(currentFdIP, host, yourUUID);
            if (resolvedList?.length > 0) [proxyConfig.host, proxyConfig.port] = resolvedList[0];
        } catch (e) {}
    } else if (['socks5', 'http', 'https', 'sstp'].includes(proxyConfig.type)) {
        shouldUseProxy = true;
    }

    const connectWithProxy = async () => {
        let newSocket;
        if (proxyConfig.type === 'socks5') newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        else if (['http', 'https'].includes(proxyConfig.type)) newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        else if (proxyConfig.type === 'sstp') newSocket = await connect2Sstp(proxyConfig, host, portNum, rawData);
        else newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        
        remoteConnWrapper.socket = newSocket;
        if (newSocket.closed) newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    };

    if (shouldUseProxy) { await connectWithProxy(); } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connectWithProxy);
        } catch (err) { await connectWithProxy(); }
    }
}

async function forwardUDP(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vmoreHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vmoreHeader) {
                        const response = new Uint8Array(vmoreHeader.length + chunk.byteLength);
                        response.set(vmoreHeader, 0); response.set(chunk, vmoreHeader.length);
                        webSocket.send(response.buffer); vmoreHeader = null;
                    } else { webSocket.send(chunk); }
                }
            }
        }));
    } catch (error) {}
}

async function handleVlsRequest(request, customFdIP) {
    const wsPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wsPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;

    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStream(serverSock, earlyData);

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardUDP(chunk, serverSock, null);
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseWsPacketHeader(chunk, yourUUID);
            if (hasError) throw new Error(message);

            if (isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }

            const respHeader = new Uint8Array([version[0], 0]);
            const rawData = chunk.slice(rawIndex);
            
            if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
            await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customFdIP);
        }
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const isUpgrade = request.headers.get('Upgrade') === 'websocket';
            let customFdIP = null;

            if (url.pathname.startsWith('/fdip=')) {
                try { customFdIP = decodeURIComponent(url.pathname.substring(9)).trim(); } catch (e) {}
                if (customFdIP && !isUpgrade) {
                    fdIP = customFdIP;
                    return new Response(`set fdIP to: ${fdIP}\n\n`, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' } });
                }
            }

            if (isUpgrade) {
                const finalFdIP = customFdIP || url.searchParams.get('fdip') || request.headers.get('fdip');
                return await handleVlsRequest(request, finalFdIP);
            }

            return new Response('Snippets Ready', { status: 200 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};
