import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildPfx, decryptPrivateKeyPem, PfxError } from "../src/lib/pfx.ts";

const dir = join(process.env.TEMP ?? "/tmp", "opencode", "pfx-fixtures");

function readText(name: string): string {
  return readFileSync(join(dir, name), "utf8");
}

let failures = 0;

function check(name: string, ok: boolean, detail?: string): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${!ok && detail ? ` :: ${detail}` : ""}`);
  if (!ok) failures++;
}

async function expectPfxError(name: string, fn: () => Promise<unknown>, includes: string) {
  try {
    await fn();
    check(name, false, "no lanzó error");
  } catch (e) {
    const err = e as Error;
    check(
      name,
      e instanceof PfxError && err.message.includes(includes),
      `got: ${err.constructor.name}: ${err.message}`
    );
  }
}

function savePfx(name: string, bytes: Uint8Array): void {
  writeFileSync(join(dir, name), Buffer.from(bytes));
  console.log(`      -> ${name} (${bytes.length} bytes)`);
}

const rsaCert = readText("rsa-cert.pem");
const rsaKey = readText("rsa-key-pkcs8.pem");
const ecCert = readText("ec-cert.pem");
const ecKeySec1 = readText("ec-key-sec1.pem");

async function main(): Promise<void> {
  // 1. RSA + contraseña
  {
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: rsaKey,
      pfxPassword: "secreto123",
    });
    savePfx("out-pass.pfx", pfx);
    check("RSA+llave con contraseña genera bytes", pfx.length > 1000);
  }

  // 2. RSA sin contraseña
  {
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: rsaKey,
      pfxPassword: "",
    });
    savePfx("out-empty.pfx", pfx);
    check("RSA+llave sin contraseña genera bytes", pfx.length > 1000);
  }

  // 3. Solo certificado
  {
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      pfxPassword: "secreto123",
    });
    savePfx("out-certonly.pfx", pfx);
    check("Solo certificado genera bytes", pfx.length > 500);
  }

  // 4. EC P-256 (SEC1 -> PKCS#8 wrap)
  {
    const pfx = await buildPfx({
      certificatePem: ecCert,
      privateKeyPem: ecKeySec1,
      pfxPassword: "secreto123",
    });
    savePfx("out-ec.pfx", pfx);
    check("EC P-256 con llave SEC1 genera bytes", pfx.length > 700);
  }

  // 5. Llave cifrada PBES2 (AES-256) como entrada
  {
    const encKey256 = readText("rsa-key-enc-aes256.pem");
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: encKey256,
      keyPassword: "clave123",
      pfxPassword: "secreto123",
    });
    savePfx("out-enc256.pfx", pfx);
    check("Llave cifrada AES-256 descifrada e incluida", pfx.length > 1000);
  }

  // 6. Llave cifrada AES-128 como entrada
  {
    const encKey128 = readText("rsa-key-enc-aes128.pem");
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: encKey128,
      keyPassword: "clave123",
      pfxPassword: "secreto123",
    });
    savePfx("out-enc128.pfx", pfx);
    check("Llave cifrada AES-128 descifrada e incluida", pfx.length > 1000);
  }

  // 7. Contraseña de llave incorrecta
  await expectPfxError(
    "contraseña de llave incorrecta -> error",
    () =>
      buildPfx({
        certificatePem: rsaCert,
        privateKeyPem: readText("rsa-key-enc-aes256.pem"),
        keyPassword: "mala",
        pfxPassword: "secreto123",
      }),
    "incorrecta"
  );

  // 8. Llave PEM tradicional cifrada con AES-256
  {
    const tradEnc = readText("rsa-key-trad-enc.pem");
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: tradEnc,
      keyPassword: "clave123",
      pfxPassword: "secreto123",
    });
    savePfx("out-tradenc.pfx", pfx);
    check("PEM tradicional cifrado AES-256 descifrado e incluido", pfx.length > 1000);
  }

  // 9. Llave PEM tradicional cifrada con 3DES -> error legible
  await expectPfxError(
    "PEM tradicional 3DES -> error legible",
    () =>
      buildPfx({
        certificatePem: rsaCert,
        privateKeyPem: readText("rsa-key-trad-enc-3des.pem"),
        keyPassword: "clave123",
        pfxPassword: "secreto123",
      }),
    "antiguo"
  );

  // 10. decryptPrivateKeyPem devuelve el PKCS#8 original
  {
    const decrypted = await decryptPrivateKeyPem(
      readText("rsa-key-enc-aes256.pem"),
      "clave123"
    );
    const original = rsaKey.replace(/\s+/g, "");
    const got = decrypted.replace(/\s+/g, "");
    check("decryptPrivateKeyPem AES-256 == PKCS#8 original", got === original);
  }
  {
    const decrypted = await decryptPrivateKeyPem(
      readText("rsa-key-enc-aes128.pem"),
      "clave123"
    );
    const original = rsaKey.replace(/\s+/g, "");
    const got = decrypted.replace(/\s+/g, "");
    check("decryptPrivateKeyPem AES-128 == PKCS#8 original", got === original);
  }

  // 11. Contraseña incorrecta en decryptPrivateKeyPem
  await expectPfxError(
    "decryptPrivateKeyPem contraseña mala -> error",
    () => decryptPrivateKeyPem(readText("rsa-key-enc-aes256.pem"), "mala"),
    "incorrecta"
  );

  // 12. Contraseña del PFX con acentos (codificación UTF-8)
  {
    const pfx = await buildPfx({
      certificatePem: rsaCert,
      privateKeyPem: rsaKey,
      pfxPassword: "secreto áéíñ",
    });
    savePfx("out-accented.pfx", pfx);
    check("PFX con contraseña acentuada genera bytes", pfx.length > 1000);
  }

  console.log(failures === 0 ? "\nTODO OK" : `\n${failures} FALLOS`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("ERROR no controlado:", e);
  process.exit(1);
});
