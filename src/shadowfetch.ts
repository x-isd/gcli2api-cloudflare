import { connect } from 'cloudflare:sockets';

// Minimal shadowfetch adaptation for outbound privacy-preserving requests.
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const HEADER_FILTER_RE = /^(host|accept-encoding|cf-)/i;

type ByteArray = Uint8Array<ArrayBufferLike>;
type ParsedHeaders = { status: number; statusText: string; headers: Headers; headerEnd: number };
type Reader = ReadableStreamDefaultReader<ByteArray>;

function concatUint8Arrays(...arrays: ByteArray[]): ByteArray {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total) as ByteArray;
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function parseHttpHeaders(buff: ByteArray): ParsedHeaders | null {
  const text = decoder.decode(buff);
  const headerEnd = text.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;
  const headerSection = text.slice(0, headerEnd).split('\r\n');
  const statusLine = headerSection[0] ?? '';
  const statusMatch = statusLine.match(/HTTP\/1\.[01] (\d+) (.*)/);
  if (!statusMatch) throw new Error(`Invalid status line: ${statusLine}`);
  const headers = new Headers();
  for (let i = 1; i < headerSection.length; i++) {
    const line = headerSection[i];
    const idx = line.indexOf(': ');
    if (idx !== -1) {
      headers.append(line.slice(0, idx), line.slice(idx + 2));
    }
  }
  return { status: Number(statusMatch[1]), statusText: statusMatch[2], headers, headerEnd };
}

async function* readChunks(
  reader: Reader,
  buff: ByteArray = new Uint8Array() as ByteArray,
): AsyncGenerator<ByteArray, void> {
  let buffer = buff;
  while (true) {
    let pos = -1;
    for (let i = 0; i < buffer.length - 1; i++) {
      if (buffer[i] === 13 && buffer[i + 1] === 10) {
        pos = i;
        break;
      }
    }
    if (pos === -1) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) buffer = concatUint8Arrays(buffer, value);
      continue;
    }
    const size = Number.parseInt(decoder.decode(buffer.slice(0, pos)), 16);
    if (Number.isNaN(size)) {
      throw new Error('Invalid chunk size');
    }
    if (!size) break;
    buffer = buffer.slice(pos + 2);
    while (buffer.length < size + 2) {
      const { value, done } = await reader.read();
      if (done) throw new Error('Unexpected EOF in chunked encoding');
      if (value) buffer = concatUint8Arrays(buffer, value);
    }
    yield buffer.slice(0, size);
    buffer = buffer.slice(size + 2);
  }
}

async function parseResponse(reader: Reader, onDone?: () => void): Promise<Response> {
  let buffer = new Uint8Array() as ByteArray;
  while (true) {
    const { value, done } = await reader.read();
    if (value) {
      buffer = concatUint8Arrays(buffer, value);
      const parsed = parseHttpHeaders(buffer);
      if (parsed) {
        const { status, statusText, headers, headerEnd } = parsed;
        const isChunked = headers.get('transfer-encoding')?.toLowerCase().includes('chunked');
        const contentLength = Number.parseInt(headers.get('content-length') ?? '0', 10);
        const data = buffer.slice(headerEnd + 4);
        const stream = new ReadableStream<ByteArray>({
          async start(controller) {
            try {
              if (isChunked) {
                for await (const chunk of readChunks(reader, data)) {
                  controller.enqueue(chunk);
                }
              } else {
                let received = data.length;
                if (data.length) controller.enqueue(data);
                while (contentLength && received < contentLength) {
                  const { value: bodyChunk, done: bodyDone } = await reader.read();
                  if (bodyDone) break;
                  if (bodyChunk) {
                    received += bodyChunk.length;
                    controller.enqueue(bodyChunk);
                  }
                }
              }
            } catch (error) {
              controller.error(error);
              return;
            } finally {
              onDone?.();
            }
            controller.close();
          },
          cancel() {
            onDone?.();
          },
        });
        return new Response(stream, { status, statusText, headers });
      }
    }
    if (done) break;
  }
  onDone?.();
  throw new Error('Unable to parse response headers');
}

export async function shadowFetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  const cleanedHeaders = new Headers();
  for (const [key, value] of request.headers) {
    if (!HEADER_FILTER_RE.test(key)) {
      cleanedHeaders.set(key, value);
    }
  }

  const bodyBytes = request.body ? (new Uint8Array(await request.arrayBuffer()) as ByteArray) : null;

  cleanedHeaders.set('Host', url.hostname);
  cleanedHeaders.set('accept-encoding', 'identity');
  cleanedHeaders.set('Connection', 'close');
  if (bodyBytes && !cleanedHeaders.has('content-length')) {
    cleanedHeaders.set('content-length', String(bodyBytes.byteLength));
  }

  const headerText = Array.from(cleanedHeaders.entries())
    .map(([k, v]) => `${k}: ${v}`)
    .join('\r\n');
  const path = `${url.pathname || '/'}${url.search}`;

  const isSecure = url.protocol === 'https:';
  const port = url.port ? Number(url.port) : isSecure ? 443 : 80;
  const socket = await connect(
    { hostname: url.hostname, port },
    { secureTransport: isSecure ? 'on' : 'off', allowHalfOpen: false },
  );

  const writer = socket.writable.getWriter();
  const requestHead = `${request.method} ${path} HTTP/1.1\r\n${headerText}\r\n\r\n`;
  await writer.write(encoder.encode(requestHead));
  if (bodyBytes) {
    await writer.write(bodyBytes);
  }
  writer.releaseLock();

  const reader = socket.readable.getReader();
  const close = () => {
    try {
      reader.releaseLock();
    } catch {
      // ignore
    }
    try {
      socket.close();
    } catch {
      // ignore
    }
  };
  return parseResponse(reader, close);
}
