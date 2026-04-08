import { connect } from 'cloudflare:sockets';

let fdIP = 'proxyip.example.com!txt';
let yourUUID = '495c7195-85b8-498a-bf20-2ea9ce9175b5';

let 缓存反代IP = null;
let 缓存反代解析数组 = null;

const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^\[?([a-fA-F0-9:]+)\]?$/;
const SPEEDTEST_DOMAINS = new Set(['speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'ovo.speedtestcustom.com']);

function formatIdentifier(arr, offset = 0) {
    const hex = Array.from(arr.slice(offset, offset + 16))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = Uint8Array.from(binaryString, c => c.charCodeAt(0));
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

function closeSocketQuietly(socket) {
    try {
        if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) {}
}

function isSpeedTestSite(hostname) {
    if (SPEEDTEST_DOMAINS.has(hostname)) return true;
    return [...SPEEDTEST_DOMAINS].some(domain => hostname.endsWith('.' + domain));
}

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();

    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        try {
            const url = new URL(proxyStr.replace(/^socks:\/\//, 'socks5://'));
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) { return null; }
    }

    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const isHttps = proxyStr.startsWith('https://');
            const url = new URL(proxyStr);
            return {
                type: isHttps ? 'https' : 'http',
                host: url.hostname,
                port: parseInt(url.port) || (isHttps ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
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
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }

    return { type: 'direct', host: proxyStr, port: 443 };
}

async function DoH查询(域名, 记录类型) {
    const fetchDns = async (dohUrl) => {
        try {
            const response = await fetch(`${dohUrl}?name=${域名}&type=${记录类型}`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            if (response.ok) {
                const data = await response.json();
                return data.Answer || [];
            }
        } catch (error) {}
        return null;
    };

    const res = await fetchDns('https://1.1.1.1/dns-query');
    return res || (await fetchDns('https://dns.google/dns-query')) || [];
}

function 解析地址端口字符串(str) {
    let addr = str, port = 443;
    const match = str.match(/^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/);
    if (match) {
        addr = match[1] || match[2];
        port = match[3] ? parseInt(match[3], 10) : 443;
    }
    return [addr, port];
}

async function 解析地址端口(fdIPStr, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
    const rawFdIP = fdIPStr.trim();
    if (缓存反代IP === rawFdIP && 缓存反代解析数组) {
        return 缓存反代解析数组;
    }

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
            const [aRecords, aaaaRecords] = await Promise.all([
                DoH查询(地址, 'A'),
                DoH查询(地址, 'AAAA')
            ]);
            const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
            const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
            const ipAddresses = [...ipv4List, ...ipv6List];
            
            所有反代数组 = ipAddresses.length > 0 ? ipAddresses.map(ip => [ip, 端口]) : [[地址, 端口]];
        } else {
            所有反代数组 = [[地址, 端口]];
        }
    }

    const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
    const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
    let 随机种子 = [...(目标根域名 + UUID)].reduce((acc, char) => acc + char.charCodeAt(0), 0);

    缓存反代解析数组 = [...排序后数组].sort(() => {
        随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff;
        return (随机种子 / 0x7fffffff) - 0.5;
    }).slice(0, 8);
    
    缓存反代IP = rawFdIP;
    return 缓存反代解析数组;
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const isUpgrade = request.headers.get('Upgrade') === 'websocket';
            let customFdIP = null;

            if (url.pathname.startsWith('/fdip=')) {
                try {
                    customFdIP = decodeURIComponent(url.pathname.substring(9)).trim();
                } catch (e) {}
                
                if (customFdIP && !isUpgrade) {
                    fdIP = customFdIP;
                    return new Response(`set fdIP to: ${fdIP}\n\n`, {
                        headers: {
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            if (isUpgrade) {
                const finalFdIP = customFdIP || url.searchParams.get('fdip') || request.headers.get('fdip');
                return await handleVlsRequest(request, finalFdIP);
            }

            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

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
            if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');

            if (isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }

            const respHeader = new Uint8Array([version[0], 0]);
            const rawData = chunk.slice(rawIndex);
            
            if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
            await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customFdIP);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

async function connect2Socks5({ host, port, username, password }, targetHost, targetPort, initialData) {
    let socket;
    try {
        socket = connect({ hostname: host, port });
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        const authMethods = (username && password) ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        
        if (methodResponse.done || methodResponse.value.byteLength < 2) throw new Error('S5 method selection failed');

        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) throw new Error('S5 requires authentication');
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) throw new Error('S5 authentication failed');
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }

        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket.set([0x05, 0x01, 0x00, 0x03, hostBytes.length]);
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        
        await writer.write(connectPacket);
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) throw new Error('S5 connection failed');

        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        if (socket) closeSocketQuietly(socket);
        throw error;
    }
}

async function connect2Http({ type, host, port, username, password }, targetHost, targetPort, initialData) {
    let socket;
    try {
        const options = type === 'https' ? { secureTransport: 'on', allowHalfOpen: false } : {};
        socket = connect({ hostname: host, port }, options);
        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        let req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
        if (username && password) req += `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`;
        req += `User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        
        await writer.write(new TextEncoder().encode(req));
        
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        const startTime = Date.now();

        while (headerEndIndex === -1 && responseBuffer.length < 8192) {
            if (Date.now() - startTime > 10000) throw new Error('connection timeout');
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed before HTTP response');

            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 13 && responseBuffer[i+1] === 10 && responseBuffer[i+2] === 13 && responseBuffer[i+3] === 10) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }

        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');

        const statusLine = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch || parseInt(statusMatch[1]) < 200 || parseInt(statusMatch[1]) >= 300) {
            throw new Error(`Connection failed: ${statusLine}`);
        }

        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        if (socket) closeSocketQuietly(socket);
        throw error;
    }
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
            if (resolvedList?.length > 0) {
                [proxyConfig.host, proxyConfig.port] = resolvedList[0];
            }
        } catch (e) {}
    } else if (['socks5', 'http', 'https'].includes(proxyConfig.type)) {
        shouldUseProxy = true;
    }

    const connectWithProxy = async () => {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (['http', 'https'].includes(proxyConfig.type)) {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    };

    if (shouldUseProxy) {
        await connectWithProxy();
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connectWithProxy);
        } catch (err) {
            await connectWithProxy();
        }
    }
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
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            hostname = Array.from({ length: 8 }, (_, i) => ipv6View.getUint16(i * 2).toString(16)).join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
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
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
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
            } else {
                webSocket.send(chunk);
            }
        },
        abort() {},
    })).catch(() => closeSocketQuietly(webSocket));
    
    if (!hasData && retryFunc) await retryFunc();
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
                        webSocket.send(response.buffer);
                        vmoreHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {}
}
