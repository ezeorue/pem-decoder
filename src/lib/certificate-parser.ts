import {
  X509Certificate,
  SubjectAlternativeNameExtension,
  KeyUsagesExtension,
  ExtendedKeyUsageExtension,
  BasicConstraintsExtension,
  KeyUsageFlags,
} from "@peculiar/x509";

export interface DecodedCertificate {
  version: number;
  serialNumber: string;

  subject: {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
    email?: string;
    raw: string;
  };

  issuer: {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    country?: string;
    state?: string;
    locality?: string;
    raw: string;
  };

  validity: {
    notBefore: Date;
    notAfter: Date;
    daysRemaining: number;
    status: "valid" | "expiring-soon" | "expired";
  };

  subjectAlternativeNames: {
    type: "DNS" | "IP" | "URI" | "EMAIL" | "OTHER";
    value: string;
  }[];

  signatureAlgorithm: string;

  publicKey: {
    algorithm: string;
    size?: number;
    curve?: string;
  };

  keyUsage: string[];

  extendedKeyUsage: string[];

  basicConstraints: {
    ca?: boolean;
    pathLength?: number;
  };

  fingerprints: {
    sha256?: string;
    sha1?: string;
    md5?: string;
  };

  extensions: { type: string; critical: boolean }[];

  pem: string;
}

// Known OIDs for extensions
const OID_SAN = "2.5.29.17";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";

// Extended Key Usage OID → name
const EKU_NAMES: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "Autenticación de servidor",
  "1.3.6.1.5.5.7.3.2": "Autenticación de cliente",
  "1.3.6.1.5.5.7.3.3": "Firma de código",
  "1.3.6.1.5.5.7.3.4": "Protección de correo",
  "1.3.6.1.5.5.7.3.8": "Marca de tiempo",
  "1.3.6.1.5.5.7.3.9": "Firma OCSP",
};

const EKU_ENUM: Record<string, string> = {
  serverAuth: "Autenticación de servidor",
  clientAuth: "Autenticación de cliente",
  codeSigning: "Firma de código",
  emailProtection: "Protección de correo",
  timeStamping: "Marca de tiempo",
  ocspSigning: "Firma OCSP",
};

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function digest(algo: string, data: ArrayBuffer): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const buf = await subtle.digest(algo, data);
  return hex(buf);
}

function parseNameParts(raw: string) {
  const result: Record<string, string | undefined> = { raw };

  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^"|"$/g, "");

    switch (key) {
      case "CN":
      case "commonName":
        result.commonName = value;
        break;
      case "O":
      case "organization":
        result.organization = value;
        break;
      case "OU":
      case "organizationalUnit":
        result.organizationalUnit = value;
        break;
      case "C":
      case "country":
        result.country = value;
        break;
      case "ST":
      case "state":
        result.state = value;
        break;
      case "L":
      case "locality":
        result.locality = value;
        break;
      case "E":
      case "emailAddress":
      case "email":
        result.email = value;
        break;
    }
  }

  return {
    commonName: result.commonName,
    organization: result.organization,
    organizationalUnit: result.organizationalUnit,
    country: result.country,
    state: result.state,
    locality: result.locality,
    email: result.email,
    raw,
  };
}

function parseSAN(cert: X509Certificate): DecodedCertificate["subjectAlternativeNames"] {
  const san: DecodedCertificate["subjectAlternativeNames"] = [];

  try {
    const ext = cert.getExtension<SubjectAlternativeNameExtension>(OID_SAN);
    if (ext instanceof SubjectAlternativeNameExtension) {
      for (const item of ext.names.items) {
        let type: "DNS" | "IP" | "URI" | "EMAIL" | "OTHER" = "OTHER";
        if (item.type === "dns") type = "DNS";
        else if (item.type === "ip") type = "IP";
        else if (item.type === "url") type = "URI";
        else if (item.type === "email") type = "EMAIL";
        san.push({ type, value: item.value });
      }
    }
  } catch {
    // SAN not parseable
  }

  return san;
}

function parseKeyUsage(cert: X509Certificate): string[] {
  const usage: string[] = [];

  try {
    const ext = cert.getExtension<KeyUsagesExtension>(OID_KEY_USAGE);
    if (ext instanceof KeyUsagesExtension) {
      const flags = ext.usages;
      if (flags & KeyUsageFlags.digitalSignature) usage.push("Firma digital");
      if (flags & KeyUsageFlags.nonRepudiation) usage.push("No repudio");
      if (flags & KeyUsageFlags.keyEncipherment) usage.push("Cifrado de clave");
      if (flags & KeyUsageFlags.dataEncipherment) usage.push("Cifrado de datos");
      if (flags & KeyUsageFlags.keyAgreement) usage.push("Acuerdo de clave");
      if (flags & KeyUsageFlags.keyCertSign) usage.push("Firma de certificados");
      if (flags & KeyUsageFlags.cRLSign) usage.push("Firma de CRL");
      if (flags & KeyUsageFlags.encipherOnly) usage.push("Solo cifrado");
      if (flags & KeyUsageFlags.decipherOnly) usage.push("Solo descifrado");
    }
  } catch {
    // KeyUsage not parseable
  }

  return usage;
}

function parseExtendedKeyUsage(cert: X509Certificate): string[] {
  const usage: string[] = [];

  try {
    const ext = cert.getExtension<ExtendedKeyUsageExtension>(OID_EXT_KEY_USAGE);
    if (ext instanceof ExtendedKeyUsageExtension) {
      for (const u of ext.usages) {
        const key = String(u);
        usage.push(EKU_ENUM[key] || EKU_NAMES[key] || key);
      }
    }
  } catch {
    // EKU not parseable
  }

  return usage;
}

function parseBasicConstraints(cert: X509Certificate): DecodedCertificate["basicConstraints"] {
  try {
    const ext = cert.getExtension<BasicConstraintsExtension>(OID_BASIC_CONSTRAINTS);
    if (ext instanceof BasicConstraintsExtension) {
      return { ca: ext.ca, pathLength: ext.pathLength };
    }
  } catch {
    // BasicConstraints not parseable
  }
  return {};
}

function parsePublicKey(cert: X509Certificate): DecodedCertificate["publicKey"] {
  const name = cert.signatureAlgorithm.name || "unknown";
  const hashName = cert.signatureAlgorithm.hash?.name || "";

  let algorithm = "unknown";
  let size: number | undefined;
  let curve: string | undefined;

  const lower = name.toLowerCase();
  if (lower.includes("rsa")) {
    algorithm = "RSA";
    // Try to infer key size from hash or algorithm name
    const rsaMatch = name.match(/(\d{3,4})/);
    if (rsaMatch) size = parseInt(rsaMatch[1], 10);
  } else if (lower.includes("ecdsa") || lower.includes("ec")) {
    algorithm = "ECDSA";
    const ecMatch = name.match(/P-(\d+)/);
    if (ecMatch) curve = `P-${ecMatch[1]}`;
    else if (hashName.includes("256")) curve = "P-256";
    else if (hashName.includes("384")) curve = "P-384";
    else if (hashName.includes("521")) curve = "P-521";
  } else if (lower.includes("ed25519")) {
    algorithm = "Ed25519";
    curve = "Ed25519";
  } else if (lower.includes("ed448")) {
    algorithm = "Ed448";
    curve = "Ed448";
  } else {
    algorithm = name;
  }

  return { algorithm, size, curve };
}

/**
 * Parse a certificate in any supported format (PEM string or DER ArrayBuffer).
 * Returns null on failure.
 * Fingerprints are computed asynchronously — the returned promise resolves
 * once all fingerprints are ready.
 */
export async function parseCertificate(
  input: string | ArrayBuffer
): Promise<DecodedCertificate | null> {
  try {
    const cert = new X509Certificate(input);
    const pem =
      typeof input === "string"
        ? input.includes("-----BEGIN")
          ? input
          : cert.toString("pem")
        : cert.toString("pem");
    return await normalizeCertificate(cert, pem);
  } catch (err) {
    console.error("Error parsing certificate:", err);
    return null;
  }
}

// ─── Format detection & conversion ────────────────────────────────────────────

export type CertFormat = "pem" | "der" | "pkcs7" | "unknown";

/**
 * Detect the certificate format from raw file bytes.
 */
export function detectCertFormat(data: ArrayBuffer): CertFormat {
  const bytes = new Uint8Array(data);

  // Check for PEM header (ASCII: 0x2D = '-')
  if (bytes.length >= 11 && bytes[0] === 0x2d && bytes[1] === 0x2d && bytes[2] === 0x2d) {
    const header = new TextDecoder().decode(bytes.subarray(0, 64));
    if (header.includes("BEGIN CERTIFICATE")) return "pem";
    if (header.includes("BEGIN PKCS7") || header.includes("BEGIN CMS")) return "pkcs7";
    return "pem"; // some other PEM block — still treat as text
  }

  // DER: starts with SEQUENCE tag 0x30
  if (bytes.length > 4 && bytes[0] === 0x30) {
    return "der";
  }

  return "unknown";
}

/**
 * Convert DER bytes to a PEM string.
 */
export function derToPem(data: ArrayBuffer): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Convert a raw file (any format) into a PEM string ready for X509Certificate.
 * Returns the PEM string, or null if the format is not recognized.
 */
export function fileToPem(data: ArrayBuffer): string | null {
  const format = detectCertFormat(data);
  switch (format) {
    case "pem":
      return new TextDecoder().decode(data);
    case "der":
      return derToPem(data);
    default:
      return null;
  }
}

// ─── Private key ──────────────────────────────────────────────────────────────

export interface PrivateKeyInfo {
  /** The PEM text of the private key (encrypted or not) */
  pem: string;
  /** Detected algorithm (e.g. "RSA", "ECDSA", "Ed25519") */
  algorithm: string;
  /** Key size in bits (RSA) if determinable */
  size?: number;
  /** Curve name (EC) if determinable */
  curve?: string;
  /** True when the PEM is passphrase-protected (BEGIN ENCRYPTED PRIVATE KEY) */
  encrypted: boolean;
  /** PKCS#8 ("PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY" / "EC PRIVATE KEY"), or "UNKNOWN" */
  format: "pkcs8" | "pkcs1" | "pkcs8-encrypted" | "pkcs1-encrypted" | "unknown";
  /** True when a certificate was also loaded and the keys appear to match */
  matchesCertificate: boolean | null;
}

/**
 * Detect the private key format from a PEM string.
 */
function detectKeyFormat(pem: string): PrivateKeyInfo["format"] {
  if (pem.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----")) return "pkcs8-encrypted";
  const traditionalEncrypted = pem.includes("Proc-Type: 4,ENCRYPTED");
  if (pem.includes("-----BEGIN RSA PRIVATE KEY-----")) return traditionalEncrypted ? "pkcs1-encrypted" : "pkcs1";
  if (pem.includes("-----BEGIN EC PRIVATE KEY-----")) return traditionalEncrypted ? "pkcs1-encrypted" : "pkcs1";
  if (pem.includes("-----BEGIN PRIVATE KEY-----")) return "pkcs8";
  return "unknown";
}

/**
 * Try to extract algorithm / size / curve from PEM headers or ASN.1 content.
 */
function inferKeyDetails(pem: string, format: PrivateKeyInfo["format"]): {
  algorithm: string;
  size?: number;
  curve?: string;
} {
  if (format === "pkcs1" || format === "pkcs1-encrypted") {
    if (pem.includes("-----BEGIN RSA PRIVATE KEY-----")) {
      // Encrypted traditional PEM: content is ciphertext, skip heuristics.
      if (format === "pkcs1-encrypted") return { algorithm: "RSA" };
      // Infer key size by decoding a bit of the base64
      const b64 = pem
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "");
      try {
        const bin = atob(b64.slice(0, 256));
        // Crude heuristic: look for large INTEGER modulus
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        // Search for a long run of 0x00-prefixed high bytes (RSA modulus)
        for (let i = 0; i < bytes.length - 4; i++) {
          if (bytes[i] === 0x00 && bytes[i + 1] === 0x82) {
            const len = (bytes[i + 2] << 8) | bytes[i + 3];
            if (len >= 128 && len <= 512) {
              return { algorithm: "RSA", size: len * 8 };
            }
          }
        }
      } catch {
        // fall through
      }
      return { algorithm: "RSA" };
    }
    if (pem.includes("-----BEGIN EC PRIVATE KEY-----")) {
      return { algorithm: "ECDSA", curve: format === "pkcs1-encrypted" ? undefined : inferEcCurve(pem) };
    }
  }

  if (format === "pkcs8" || format === "pkcs8-encrypted") {
    // PKCS#8: AlgorithmIdentifier inside. Look for well-known OIDs in the DER.
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    try {
      const bin = atob(b64.slice(0, 512));
      if (bin.includes("\x2a\x86\x48\x86\xf7\x0d\x01\x01")) {
        // rsaEncryption OID 1.2.840.113549.1.1.1
        // Try to find key size from the modulus in the key itself
        const full = atob(b64);
        const size = findRsaModulusBits(full);
        return { algorithm: "RSA", size };
      }
      if (bin.includes("\x2a\x86\x48\xce\x3d\x02\x01") || bin.includes("\x2a\x86\x48\xce\x3d\x03\x01")) {
        // ecPublicKey OID 1.2.840.10045.2.1 or prime256v1
        return { algorithm: "ECDSA", curve: inferEcCurve(pem) };
      }
      if (bin.includes("\x2b\x65\x70")) {
        // id-Ed25519 1.3.101.112
        return { algorithm: "Ed25519", curve: "Ed25519" };
      }
      if (bin.includes("\x2b\x65\x71")) {
        // id-Ed448 1.3.101.113
        return { algorithm: "Ed448", curve: "Ed448" };
      }
    } catch {
      // fall through
    }
    return { algorithm: "Desconocido" };
  }

  return { algorithm: "Desconocido" };
}

function findRsaModulusBits(derBinary: string): number | undefined {
  // Look for SEQUENCE with a large INTEGER (the modulus)
  const bytes = new Uint8Array(derBinary.length);
  for (let i = 0; i < derBinary.length; i++) bytes[i] = derBinary.charCodeAt(i);
  for (let i = 0; i < bytes.length - 4; i++) {
    if (bytes[i] === 0x00 && bytes[i + 1] === 0x82) {
      const len = (bytes[i + 2] << 8) | bytes[i + 3];
      if (len >= 128 && len <= 512) return len * 8;
    }
  }
  return undefined;
}

function inferEcCurve(pem: string): string | undefined {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  try {
    const bin = atob(b64.slice(0, 512));
    // prime256v1 / secp256r1: 1.2.840.10045.3.1.7
    if (bin.includes("\x2a\x86\x48\xce\x3d\x03\x01\x07")) return "P-256";
    // secp384r1: 1.3.132.0.34
    if (bin.includes("\x2b\x81\x04\x00\x22")) return "P-384";
    // secp521r1: 1.3.132.0.35
    if (bin.includes("\x2b\x81\x04\x00\x23")) return "P-521";
  } catch {
    // ignore
  }
  return undefined;
}

/**
 * Parse a private key file (PEM text or DER bytes) and return its details.
 * Also checks whether it matches a given certificate (if provided).
 */
export function parsePrivateKey(
  input: string | ArrayBuffer
): PrivateKeyInfo | null {
  let pem: string;

  if (input instanceof ArrayBuffer) {
    const format = detectCertFormat(input);
    if (format === "der") {
      // DER-encoded private key (PKCS#8 or PKCS#1)
      const b64 = btoa(String.fromCharCode(...new Uint8Array(input)));
      const lines = b64.match(/.{1,64}/g) || [];
      pem = `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
    } else {
      pem = new TextDecoder().decode(input);
    }
  } else {
    pem = input;
  }

  const format = detectKeyFormat(pem);
  if (format === "unknown") return null;

  const details = inferKeyDetails(pem, format);

  const info: PrivateKeyInfo = {
    pem,
    algorithm: details.algorithm,
    size: details.size,
    curve: details.curve,
    encrypted: format === "pkcs8-encrypted" || format === "pkcs1-encrypted",
    format,
    matchesCertificate: null,
  };

  // Key match is verified asynchronously by the caller via verifyKeyMatch()
  info.matchesCertificate = null;

  return info;
}

/**
 * Async key-match verification using Web Crypto.
 * Exports the public key from the certificate and the private key,
 * then compares their SPKI DER encoding.
 */
export async function verifyKeyMatch(
  privatePem: string,
  certificatePem: string
): Promise<boolean | null> {
  try {
    const subtle = globalThis.crypto.subtle;

    // Get the certificate's public key as SPKI (DER base64)
    const cert = new X509Certificate(certificatePem);
    const certSpki = cert.publicKey.rawData;

    // Try to import the private key and export its public half
    const privBytes = pemToDer(privatePem);
    if (!privBytes) return null;

    // Try PKCS#8 first
    let privKey: CryptoKey | null = null;
    const algCandidates: { name: string; hash?: string }[] = [
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      { name: "RSA-PSS", hash: "SHA-256" },
      { name: "ECDSA", hash: "SHA-256" },
      { name: "Ed25519" },
    ];

    for (const alg of algCandidates) {
      try {
        const importParams: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams =
          alg.name.startsWith("RSA")
            ? { name: alg.name, hash: alg.hash! }
            : alg.name === "ECDSA"
              ? { name: "ECDSA", namedCurve: "P-256" }
              : { name: alg.name };
        privKey = await subtle.importKey(
          "pkcs8",
          privBytes,
          importParams as never,
          false,
          ["verify"]
        );
        break;
      } catch {
        // try next
      }
    }

    if (!privKey) return null;

    // Export public key from private key — Web Crypto doesn't support
    // direct priv→pub export for all algorithms, so we compare SPKI of
    // the certificate against a re-exported public key when possible.
    // For RSA/EC we can derive:
    try {
      const derivedSpki = await subtle.exportKey("spki", privKey);
      return buffersEqual(derivedSpki, certSpki);
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

export function pemToDer(pem: string): ArrayBuffer | null {
  try {
    const b64 = pem
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, "");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  } catch {
    return null;
  }
}

function buffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false;
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  for (let i = 0; i < va.length; i++) {
    if (va[i] !== vb[i]) return false;
  }
  return true;
}

// ─── Export helpers ───────────────────────────────────────────────────────────

/**
 * Build a HAProxy-ready PEM bundle: certificate + private key concatenated.
 * HAProxy expects `cert.pem` to contain the private key followed by the
 * certificate (or certificate chain).
 */
export function buildHaproxyBundle(certificatePem: string, privateKeyPem: string): string {
  return `${privateKeyPem.trim()}\n${certificatePem.trim()}\n`;
}

/**
 * Normalize a PEM string to ensure consistent line endings (LF) and
 * a trailing newline — required by HAProxy and most TLS servers.
 */
export function normalizePem(pem: string): string {
  return pem.replace(/\r\n/g, "\n").replace(/\s*$/, "\n");
}

async function normalizeCertificate(
  cert: X509Certificate,
  originalPem: string
): Promise<DecodedCertificate> {
  const now = new Date();

  const daysRemaining = Math.ceil(
    (cert.notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );

  let status: "valid" | "expiring-soon" | "expired";
  if (now > cert.notAfter) {
    status = "expired";
  } else if (daysRemaining < 0) {
    status = "expired";
  } else if (daysRemaining < 30) {
    status = "expiring-soon";
  } else {
    status = "valid";
  }

  const subject = parseNameParts(cert.subject);
  const issuer = parseNameParts(cert.issuer);

  const san = parseSAN(cert);
  const keyUsage = parseKeyUsage(cert);
  const extendedKeyUsage = parseExtendedKeyUsage(cert);
  const basicConstraints = parseBasicConstraints(cert);
  const publicKey = parsePublicKey(cert);

  const rawData = cert.rawData;

  const [sha256, sha1] = await Promise.all([
    digest("SHA-256", rawData),
    digest("SHA-1", rawData),
  ]);

  let md5: string | undefined;
  try {
    md5 = await digest("MD5", rawData);
  } catch {
    // MD5 not supported in this environment
  }

  const pem = cert.toString("pem");

  const exts = cert.extensions.map((e) => ({
    type: e.type,
    critical: e.critical,
  }));

  return {
    version: cert.extensions.length > 0 ? 3 : 1,
    serialNumber: cert.serialNumber,
    subject,
    issuer,
    validity: {
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      daysRemaining,
      status,
    },
    subjectAlternativeNames: san,
    signatureAlgorithm: cert.signatureAlgorithm.name,
    publicKey,
    keyUsage,
    extendedKeyUsage,
    basicConstraints,
    fingerprints: { sha256, sha1, md5 },
    extensions: exts,
    pem: originalPem || pem,
  };
}
