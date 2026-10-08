import "reflect-metadata";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { ContentInfo, id_data } from "@peculiar/asn1-cms";
import {
  AuthenticatedSafe,
  CertBag,
  MacData,
  PKCS12Attribute,
  PFX,
  SafeBag,
  SafeContents,
  id_certBag,
  id_pkcs8ShroudedKeyBag,
  id_x509Certificate,
} from "@peculiar/asn1-pfx";
import { EncryptedData, EncryptedPrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { DigestInfo, sha1 as sha1Alg } from "@peculiar/asn1-rsa";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { X509Certificate } from "@peculiar/x509";

// ─── OIDs ─────────────────────────────────────────────────────────────────────

const ID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";
const ID_FRIENDLY_NAME = "1.2.840.113549.1.9.20";
const ID_PBES2 = "1.2.840.113549.1.5.13";
const ID_PBKDF2 = "1.2.840.113549.1.5.12";
// Algunos generadores escriben PBKDF2 con este OID equivocado; lo aceptamos al leer
const ID_PBKDF2_ALT = "1.2.840.113549.1.2.12";
const ID_HMAC_SHA1 = "1.2.840.113549.2.7";
const ID_HMAC_SHA256 = "1.2.840.113549.2.9";
const ID_HMAC_SHA384 = "1.2.840.113549.2.10";
const ID_HMAC_SHA512 = "1.2.840.113549.2.11";
const ID_AES_128_CBC = "2.16.840.1.101.3.4.1.2";
const ID_AES_192_CBC = "2.16.840.1.101.3.4.1.22";
const ID_AES_256_CBC = "2.16.840.1.101.3.4.1.42";
const ID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

/** Legacy PKCS#12 / PKCS#5 PBE schemes we cannot decrypt with Web Crypto. */
const LEGACY_PBE_OIDS = new Set([
  "1.2.840.113549.1.12.1.1",
  "1.2.840.113549.1.12.1.2",
  "1.2.840.113549.1.12.1.3",
  "1.2.840.113549.1.12.1.4",
  "1.2.840.113549.1.12.1.5",
  "1.2.840.113549.1.12.1.6",
  "1.2.840.113549.1.5.1",
  "1.2.840.113549.1.5.3",
  "1.2.840.113549.1.5.4",
  "1.2.840.113549.1.5.6",
  "1.2.840.113549.1.5.10",
  "1.2.840.113549.1.5.11",
  "1.2.840.113549.1.5.12",
  "1.2.840.113549.1.9.14",
]);

const LEGACY_KEY_ERROR =
  "La llave está cifrada con un algoritmo antiguo (3DES/RC2). Convertila a un formato moderno con: openssl pkcs8 -topk8 -in llave.key -out llave-nueva.key";

// ─── Parámetros del generador ─────────────────────────────────────────────────

const MAC_ITERATIONS = 2048;
const MAC_SALT_LENGTH = 8;
const PBKDF2_ITERATIONS = 2048;
const PBKDF2_SALT_LENGTH = 16;
const PFX_VERSION = 3;

// ─── Errores en español ───────────────────────────────────────────────────────

export class PfxError extends Error {}

function wrongKeyPasswordError(): PfxError {
  return new PfxError("La contraseña de la llave privada es incorrecta.");
}

// ─── Helpers DER manuales ─────────────────────────────────────────────────────

interface Tlv {
  tag: number;
  contentStart: number;
  contentLength: number;
  end: number;
}

function concatBytes(...parts: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function derLength(length: number): Uint8Array<ArrayBuffer> {
  if (length < 0x80) return new Uint8Array([length]);
  if (length <= 0xff) return new Uint8Array([0x81, length]);
  if (length <= 0xffff) return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  return new Uint8Array([
    0x83,
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  ]);
}

function toBytes(data: ArrayBuffer | Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

function toArrayBuffer(b: Uint8Array<ArrayBuffer>): ArrayBuffer {
  if (b.byteOffset === 0 && b.byteLength === b.buffer.byteLength) return b.buffer;
  return b.slice().buffer;
}

function derTlv(tag: number, raw: ArrayBuffer | Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const content = toBytes(raw);
  if (content.length < 0x80) {
    return concatBytes(new Uint8Array([tag, content.length]), content);
  }
  return concatBytes(new Uint8Array([tag]), derLength(content.length), content);
}

function derSequence(parts: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  return derTlv(0x30, concatBytes(...parts));
}

function derOctetString(content: ArrayBuffer | Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return derTlv(0x04, content);
}

function derNull(): Uint8Array<ArrayBuffer> {
  return new Uint8Array([0x05, 0x00]);
}

function derInteger(value: number): Uint8Array<ArrayBuffer> {
  const bytes: number[] = [];
  let v = value;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return derTlv(0x02, new Uint8Array(bytes));
}

function derOid(oid: string): Uint8Array<ArrayBuffer> {
  const parts = oid.split(".").map(Number);
  const body: number[] = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let value = parts[i];
    const chunk: number[] = [value & 0x7f];
    value >>= 7;
    while (value > 0) {
      chunk.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    body.push(...chunk);
  }
  return derTlv(0x06, new Uint8Array(body));
}

function readTlv(bytes: Uint8Array<ArrayBuffer>, offset: number): Tlv {
  const tag = bytes[offset];
  let pos = offset + 1;
  let length = bytes[pos];
  pos++;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = (length << 8) | bytes[pos];
      pos++;
    }
  }
  return { tag, contentStart: pos, contentLength: length, end: pos + length };
}

function readChildren(bytes: Uint8Array<ArrayBuffer>, tlv: Tlv): Tlv[] {
  const result: Tlv[] = [];
  let pos = tlv.contentStart;
  while (pos < tlv.end) {
    const child = readTlv(bytes, pos);
    result.push(child);
    pos = child.end;
  }
  return result;
}

function contentBytes(bytes: Uint8Array<ArrayBuffer>, tlv: Tlv): Uint8Array<ArrayBuffer> {
  return bytes.subarray(tlv.contentStart, tlv.end);
}

function parseWhole(bytes: Uint8Array<ArrayBuffer>, label: string): Tlv {
  if (bytes.length === 0 || bytes[0] !== 0x30) {
    throw new PfxError(`La ${label} no es un bloque DER válido.`);
  }
  const tlv = readTlv(bytes, 0);
  if (tlv.end !== bytes.length) {
    throw new PfxError(`La ${label} contiene datos ASN.1 inesperados.`);
  }
  return tlv;
}

function oidToString(bytes: Uint8Array<ArrayBuffer>, tlv: Tlv): string {
  const body = contentBytes(bytes, tlv);
  const first = body[0];
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < body.length; i++) {
    value = (value << 7) | (body[i] & 0x7f);
    if (!(body[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function intFromTlv(bytes: Uint8Array<ArrayBuffer>, tlv: Tlv): number {
  const body = contentBytes(bytes, tlv);
  let value = 0;
  for (const b of body) value = value * 256 + b;
  return value;
}

// ─── Formato PEM ──────────────────────────────────────────────────────────────

function extractPemBlock(pem: string, label: string): Uint8Array<ArrayBuffer> | null {
  const match = pem.match(
    new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`)
  );
  if (!match) return null;
  const bodyLines = match[1].split(/\r?\n/).filter((line) => !line.includes(":"));
  const base64 = bodyLines.join("").replace(/\s+/g, "");
  try {
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

// ─── Crypto helpers (Web Crypto) ──────────────────────────────────────────────

function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

async function digestSha1(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const digest = await subtle().digest("SHA-1", data);
  return new Uint8Array(digest);
}

async function hmacSha1(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await subtle().importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = await subtle().sign("HMAC", cryptoKey, data);
  return new Uint8Array(sig);
}

async function aesCbcDecrypt(
  key: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await subtle().importKey("raw", key, { name: "AES-CBC" }, false, [
    "decrypt",
  ]);
  const plain = await subtle().decrypt({ name: "AES-CBC", iv }, cryptoKey, ciphertext);
  return new Uint8Array(plain);
}

async function pbkdf2Sha1(
  password: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  bits: number
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await subtle().importKey("raw", password, "PBKDF2", false, [
    "deriveBits",
  ]);
  const bitsOut = await subtle().deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-1" },
    cryptoKey,
    bits
  );
  return new Uint8Array(bitsOut);
}

// ─── PKCS#12 KDF (RFC 7292 B.2) ───────────────────────────────────────────────

function passwordToBmp(password: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    out[i * 2] = code >> 8;
    out[i * 2 + 1] = code & 0xff;
  }
  return out;
}

function repeatToLength(data: Uint8Array<ArrayBuffer>, length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = data[i % data.length];
  return out;
}

async function pkcs12Kdf(
  passwordBmp: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  id: number,
  outLength: number,
  iterations: number
): Promise<Uint8Array<ArrayBuffer>> {
  const u = 20;
  const v = 64;
  const diversifier = new Uint8Array(v).fill(id);
  const s = salt.length > 0 ? repeatToLength(salt, Math.ceil(salt.length / v) * v) : new Uint8Array(0);
  const p =
    passwordBmp.length > 0
      ? repeatToLength(passwordBmp, Math.ceil(passwordBmp.length / v) * v)
      : new Uint8Array(0);
  let i = concatBytes(s, p);
  const blockCount = i.length / v;
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  const c = Math.ceil(outLength / u);
  for (let round = 0; round < c; round++) {
    let a = concatBytes(diversifier, i);
    for (let it = 0; it < iterations; it++) a = await digestSha1(a);
    chunks.push(a);
    const b = repeatToLength(a, v);
    for (let block = 0; block < blockCount; block++) {
      for (let k = 0; k < v; k++) i[block * v + k] ^= b[k];
    }
  }
  return concatBytes(...chunks).subarray(0, outLength);
}

// ─── MD5 + EVP_BytesToKey (PEM tradicional cifrado) ──────────────────────────

function md5(input: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16,
    23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const k: number[] = [];
  for (let i = 0; i < 64; i++) {
    k.push(Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  }
  const length = input.length;
  const paddedLength = (((length + 8) >> 6) + 1) << 6;
  const data = new Uint8Array(paddedLength);
  data.set(input);
  data[length] = 0x80;
  const bitLength = length * 8;
  data[paddedLength - 8] = bitLength & 0xff;
  data[paddedLength - 7] = (bitLength >>> 8) & 0xff;
  data[paddedLength - 6] = (bitLength >>> 16) & 0xff;
  data[paddedLength - 5] = (bitLength >>> 24) & 0xff;
  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      words[i] =
        data[j] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24);
    }
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      f = (f + a + k[i] + words[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      b = (b + ((f << s[i]) | (f >>> (32 - s[i])))) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  const words = [a0, b0, c0, d0];
  for (let i = 0; i < 4; i++) {
    out[i * 4] = words[i] & 0xff;
    out[i * 4 + 1] = (words[i] >>> 8) & 0xff;
    out[i * 4 + 2] = (words[i] >>> 16) & 0xff;
    out[i * 4 + 3] = (words[i] >>> 24) & 0xff;
  }
  return out;
}

function evpBytesToKey(password: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, keyLength: number): Uint8Array<ArrayBuffer> {
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let previous = new Uint8Array(0);
  let total = 0;
  while (total < keyLength) {
    previous = md5(concatBytes(previous, password, salt));
    chunks.push(previous);
    total += previous.length;
  }
  return concatBytes(...chunks).subarray(0, keyLength);
}

// ─── Descifrado de llaves de entrada ─────────────────────────────────────────

const LEGACY_CIPHERS: Record<string, { keyLength: number; ivLength: number }> = {
  "AES-128-CBC": { keyLength: 16, ivLength: 16 },
  "AES-192-CBC": { keyLength: 24, ivLength: 16 },
  "AES-256-CBC": { keyLength: 32, ivLength: 16 },
};

async function decryptTraditionalPem(pem: string, password: string): Promise<Uint8Array<ArrayBuffer>> {
  const headerMatch = pem.match(/DEK-Info:\s*([A-Za-z0-9-]+),([0-9A-Fa-f]+)/);
  if (!headerMatch) {
    throw new PfxError("No se pudo leer la cabecera DEK-Info de la llave cifrada.");
  }
  const cipherName = headerMatch[1];
  const cipher = LEGACY_CIPHERS[cipherName];
  if (!cipher) {
    throw new PfxError(
      `La llave está cifrada con un algoritmo antiguo (${cipherName}). Convertila a un formato moderno con: openssl pkcs8 -topk8 -in llave.key -out llave-nueva.key`
    );
  }
  const iv = hexToBytes(headerMatch[2]);
  if (iv.length !== cipher.ivLength) {
    throw new PfxError("La cabecera DEK-Info de la llave es inválida.");
  }
  const der = extractPemBlock(pem, "RSA PRIVATE KEY") ?? extractPemBlock(pem, "EC PRIVATE KEY");
  if (!der) {
    throw new PfxError("No se pudo leer la llave privada cifrada.");
  }
  const passwordBytes = new TextEncoder().encode(password);
  const key = evpBytesToKey(passwordBytes, iv.subarray(0, 8), cipher.keyLength);
  try {
    return await aesCbcDecrypt(key, iv, der);
  } catch {
    throw wrongKeyPasswordError();
  }
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function decryptEncryptedPkcs8(der: Uint8Array<ArrayBuffer>, password: string): Promise<Uint8Array<ArrayBuffer>> {
  const outer = parseWhole(der, "llave cifrada");
  const outerKids = readChildren(der, outer);
  if (outerKids.length < 2 || outerKids[0].tag !== 0x30) {
    throw new PfxError("La llave cifrada tiene una estructura ASN.1 inválida.");
  }
  const algKids = readChildren(der, outerKids[0]);
  const algorithm = oidToString(der, algKids[0]);

  if (algorithm !== ID_PBES2) {
    if (LEGACY_PBE_OIDS.has(algorithm)) {
      throw new PfxError(LEGACY_KEY_ERROR);
    }
    throw new PfxError(`Algoritmo de cifrado de llave no soportado (${algorithm}).`);
  }

  const pbes2Kids = readChildren(der, algKids[1]);
  const kdfKids = readChildren(der, pbes2Kids[0]);
  const kdfOid = oidToString(der, kdfKids[0]);
  if (kdfOid !== ID_PBKDF2 && kdfOid !== ID_PBKDF2_ALT) {
    throw new PfxError(`Función de derivación de clave no soportada (${kdfOid}).`);
  }

  const pbkdf2Kids = readChildren(der, kdfKids[1]);
  const salt = contentBytes(der, pbkdf2Kids[0]);
  const iterations = intFromTlv(der, pbkdf2Kids[1]);
  let hashName = "SHA-1";
  let keyBits: number | undefined;
  for (let i = 2; i < pbkdf2Kids.length; i++) {
    const child = pbkdf2Kids[i];
    if (child.tag === 0x02) {
      keyBits = intFromTlv(der, child) * 8;
    } else if (child.tag === 0x30) {
      const prfKids = readChildren(der, child);
      const prfOid = oidToString(der, prfKids[0]);
      if (prfOid === ID_HMAC_SHA1) hashName = "SHA-1";
      else if (prfOid === ID_HMAC_SHA256) hashName = "SHA-256";
      else if (prfOid === ID_HMAC_SHA384) hashName = "SHA-384";
      else if (prfOid === ID_HMAC_SHA512) hashName = "SHA-512";
      else throw new PfxError(`Función de resumen no soportada (${prfOid}).`);
    }
  }

  const encKids = readChildren(der, pbes2Kids[1]);
  const encOid = oidToString(der, encKids[0]);
  let aesKeyLength: number;
  if (encOid === ID_AES_128_CBC) aesKeyLength = 16;
  else if (encOid === ID_AES_192_CBC) aesKeyLength = 24;
  else if (encOid === ID_AES_256_CBC) aesKeyLength = 32;
  else throw new PfxError(`Algoritmo de cifrado de llave no soportado (${encOid}).`);

  if (encKids.length < 2 || encKids[1].tag !== 0x04) {
    throw new PfxError("Los parámetros de cifrado de la llave son inválidos.");
  }
  const iv = contentBytes(der, encKids[1]);
  const ciphertext = contentBytes(der, outerKids[1]);

  const cryptoKey = await subtle().importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derived = new Uint8Array(
    await subtle().deriveBits(
      { name: "PBKDF2", salt, iterations, hash: hashName },
      cryptoKey,
      keyBits ?? aesKeyLength * 8
    )
  );
  let plain: Uint8Array<ArrayBuffer>;
  try {
    plain = await aesCbcDecrypt(derived, iv, ciphertext);
  } catch {
    throw wrongKeyPasswordError();
  }
  try {
    parseWhole(plain, "llave descifrada");
  } catch {
    throw wrongKeyPasswordError();
  }
  return plain;
}

// ─── Conversión a PKCS#8 ─────────────────────────────────────────────────────

function wrapPkcs1AsPkcs8(pkcs1: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return derSequence([
    derInteger(0),
    derSequence([derOid(ID_RSA_ENCRYPTION), derNull()]),
    derOctetString(pkcs1),
  ]);
}

function wrapSec1AsPkcs8(sec1: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const outer = parseWhole(sec1, "llave EC");
  const kids = readChildren(sec1, outer);
  const params = kids.find((child) => child.tag === 0xa0);
  if (!params) {
    throw new PfxError("No se pudo determinar la curva de la llave EC.");
  }
  const paramsInner = readChildren(sec1, params);
  if (paramsInner.length === 0 || paramsInner[0].tag !== 0x06) {
    throw new PfxError("No se pudo determinar la curva de la llave EC.");
  }
  const curveOid = contentBytes(sec1, paramsInner[0]);
  return derSequence([
    derInteger(0),
    derSequence([derOid(ID_EC_PUBLIC_KEY), derTlv(0x06, curveOid)]),
    derOctetString(sec1),
  ]);
}

async function resolvePkcs8(pem: string, password: string | undefined): Promise<Uint8Array<ArrayBuffer>> {
  const encrypted = extractPemBlock(pem, "ENCRYPTED PRIVATE KEY");
  if (encrypted) {
    return decryptEncryptedPkcs8(encrypted, password ?? "");
  }
  const plainPkcs8 = extractPemBlock(pem, "PRIVATE KEY");
  if (plainPkcs8) {
    parseWhole(plainPkcs8, "llave privada");
    return plainPkcs8;
  }
  const traditional = extractPemBlock(pem, "RSA PRIVATE KEY");
  if (traditional) {
    if (/Proc-Type:\s*4,ENCRYPTED/.test(pem)) {
      if (!password) {
        throw new PfxError("Ingresá la contraseña de la llave privada.");
      }
      const plain = await decryptTraditionalPem(pem, password);
      parseWhole(plain, "llave descifrada");
      return wrapPkcs1AsPkcs8(plain);
    }
    parseWhole(traditional, "llave privada");
    return wrapPkcs1AsPkcs8(traditional);
  }
  const ecKey = extractPemBlock(pem, "EC PRIVATE KEY");
  if (ecKey) {
    if (/Proc-Type:\s*4,ENCRYPTED/.test(pem)) {
      if (!password) {
        throw new PfxError("Ingresá la contraseña de la llave privada.");
      }
      const plain = await decryptTraditionalPem(pem, password);
      parseWhole(plain, "llave descifrada");
      return wrapSec1AsPkcs8(plain);
    }
    parseWhole(ecKey, "llave privada");
    return wrapSec1AsPkcs8(ecKey);
  }
  throw new PfxError("Formato de llave privada no reconocido.");
}

// ─── PBES2: armado de parámetros ─────────────────────────────────────────────

function buildPbes2Params(salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  return derSequence([
    derSequence([
      derOid(ID_PBKDF2),
      derSequence([
        derOctetString(salt),
        derInteger(PBKDF2_ITERATIONS),
        derSequence([derOid(ID_HMAC_SHA1), derNull()]),
      ]),
    ]),
    derSequence([derOid(ID_AES_256_CBC), derOctetString(iv)]),
  ]);
}

async function shroudKey(pkcs8: Uint8Array<ArrayBuffer>, pfxPassword: string): Promise<EncryptedPrivateKeyInfo> {
  const salt = randomBytes(PBKDF2_SALT_LENGTH);
  const iv = randomBytes(16);
  const key = await pbkdf2Sha1(
    new TextEncoder().encode(pfxPassword),
    salt,
    PBKDF2_ITERATIONS,
    256
  );
  const cryptoKey = await subtle().importKey("raw", key, { name: "AES-CBC" }, false, [
    "encrypt",
  ]);
  const ciphertext = new Uint8Array(
    await subtle().encrypt({ name: "AES-CBC", iv }, cryptoKey, pkcs8)
  );
  return new EncryptedPrivateKeyInfo({
    encryptionAlgorithm: new AlgorithmIdentifier({
      algorithm: ID_PBES2,
      parameters: toArrayBuffer(buildPbes2Params(salt, iv)),
    }),
    encryptedData: new EncryptedData(ciphertext),
  });
}

// ─── Atributos PKCS#12 ───────────────────────────────────────────────────────

function makeBagAttributes(localKeyId: Uint8Array<ArrayBuffer>, friendlyName: string): PKCS12Attribute[] {
  const keyIdAttr = new PKCS12Attribute();
  keyIdAttr.attrId = ID_LOCAL_KEY_ID;
  keyIdAttr.attrValues = [toArrayBuffer(derOctetString(localKeyId))];

  const nameAttr = new PKCS12Attribute();
  nameAttr.attrId = ID_FRIENDLY_NAME;
  const utf16 = passwordToBmp(friendlyName).subarray(0, friendlyName.length * 2);
  nameAttr.attrValues = [toArrayBuffer(derTlv(0x1e, utf16))];

  return [nameAttr, keyIdAttr];
}

// ─── Generación del PFX ──────────────────────────────────────────────────────

export interface PfxBuildOptions {
  certificatePem: string;
  privateKeyPem?: string;
  keyPassword?: string;
  pfxPassword?: string;
}

export async function buildPfx(options: PfxBuildOptions): Promise<Uint8Array<ArrayBuffer>> {
  const pfxPassword = options.pfxPassword ?? "";
  const certDer = extractPemBlock(options.certificatePem, "CERTIFICATE");
  if (!certDer) {
    throw new PfxError("No se pudo leer el certificado para generar el .pfx.");
  }

  const cert = new X509Certificate(certDer);
  const localKeyId = await digestSha1(certDer);
  let friendlyName = "";
  try {
    friendlyName = cert.subjectName.getField("CN")[0] ?? "";
  } catch {
    friendlyName = "";
  }
  if (!friendlyName) friendlyName = cert.subject;

  const attributes = makeBagAttributes(localKeyId, friendlyName);

  const certBag = new CertBag({
    certId: id_x509Certificate,
    certValue: toArrayBuffer(derOctetString(certDer)),
  });
  const certSafeBag = new SafeBag({
    bagId: id_certBag,
    bagValue: AsnConvert.serialize(certBag),
    bagAttributes: attributes,
  });

  const bags: SafeBag[] = [certSafeBag];

  if (options.privateKeyPem) {
    const pkcs8 = await resolvePkcs8(options.privateKeyPem, options.keyPassword);
    const shrouded = await shroudKey(pkcs8, pfxPassword);
    const keyBag = new SafeBag({
      bagId: id_pkcs8ShroudedKeyBag,
      bagValue: AsnConvert.serialize(shrouded),
      bagAttributes: attributes,
    });
    bags.push(keyBag);
  }

  const certSafeContents = new SafeContents([certSafeBag]);
  const certSafeDer = AsnConvert.serialize(certSafeContents);
  const certContentInfo = new ContentInfo({
    contentType: id_data,
    content: toArrayBuffer(derOctetString(certSafeDer)),
  });

  const contentInfos: ContentInfo[] = [certContentInfo];

  if (bags.length > 1) {
    const keySafeContents = new SafeContents([bags[1]]);
    const keySafeDer = AsnConvert.serialize(keySafeContents);
    contentInfos.push(
      new ContentInfo({ contentType: id_data, content: toArrayBuffer(derOctetString(keySafeDer)) })
    );
  }

  const authenticatedSafe = new AuthenticatedSafe(contentInfos);
  const authenticatedSafeDer = AsnConvert.serialize(authenticatedSafe);

  const authContentInfo = new ContentInfo({
    contentType: id_data,
    content: toArrayBuffer(derOctetString(authenticatedSafeDer)),
  });

  const macSalt = randomBytes(MAC_SALT_LENGTH);
  const macKey = await pkcs12Kdf(
    passwordToBmp(pfxPassword),
    macSalt,
    3,
    20,
    MAC_ITERATIONS
  );
  const mac = await hmacSha1(macKey, toBytes(authenticatedSafeDer));

  const digestInfo = new DigestInfo({
    digestAlgorithm: new AlgorithmIdentifier(sha1Alg),
    digest: new OctetString(mac),
  });
  const macData = new MacData({
    mac: digestInfo,
    macSalt: new OctetString(macSalt),
    iterations: MAC_ITERATIONS,
  });

  const pfx = new PFX({
    version: PFX_VERSION,
    authSafe: authContentInfo,
    macData,
  });

  return new Uint8Array(AsnConvert.serialize(pfx));
}

// ─── Descifrado público (para pruebas / reutilización) ────────────────────────

export async function decryptPrivateKeyPem(pem: string, password: string): Promise<string> {
  const der = await resolvePkcs8(pem, password);
  const base64 = btoa(String.fromCharCode(...der));
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}

export { extractPemBlock as extractPemBlockForTests };
