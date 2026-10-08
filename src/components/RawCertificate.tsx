import { useState, type ReactNode } from "react";
import { Download, Copy, FileDown, KeyRound, Lock, Package } from "lucide-react";
import { normalizePem, buildHaproxyBundle } from "../lib/certificate-parser";
import type { PrivateKeyInfo } from "../lib/certificate-parser";
import { buildPfx } from "../lib/pfx";

interface RawCertificateProps {
  pem: string;
  privateKey: PrivateKeyInfo | null;
}

type ExportMode = "cert" | "key" | "bundle" | "pfx";

export function RawCertificate({ pem, privateKey }: RawCertificateProps) {
  const [showCopy, setShowCopy] = useState(false);
  const [exportMode, setExportMode] = useState<ExportMode>("cert");
  const [pfxPassword, setPfxPassword] = useState("");
  const [keyPassword, setKeyPassword] = useState("");
  const [pfxError, setPfxError] = useState("");
  const [pfxBuilding, setPfxBuilding] = useState(false);
  const [pfxReady, setPfxReady] = useState(false);

  const hasKey = privateKey !== null;
  const canExportKey = hasKey && !privateKey!.encrypted;
  const keyNeedsPassword = hasKey && privateKey!.encrypted;
  const keyMismatch = hasKey && privateKey!.matchesCertificate === false;

  const getExportContent = (): string => {
    switch (exportMode) {
      case "cert":
        return normalizePem(pem);
      case "key":
        return canExportKey ? normalizePem(privateKey!.pem) : "";
      case "bundle":
        return canExportKey ? buildHaproxyBundle(pem, privateKey!.pem) : normalizePem(pem);
      case "pfx":
        return "";
    }
  };

  const getExportFilename = (): string => {
    switch (exportMode) {
      case "cert":
        return "certificado.pem";
      case "key":
        return "llave-privada.pem";
      case "bundle":
        return "certificado-y-llave.pem";
      case "pfx":
        return hasKey ? "certificado-y-llave.pfx" : "certificado.pfx";
    }
  };

  const selectMode = (mode: ExportMode) => {
    setExportMode(mode);
    setPfxError("");
    setPfxReady(false);
  };

  const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(getExportContent());
    setShowCopy(true);
    setTimeout(() => setShowCopy(false), 2000);
  };

  const handlePfxDownload = async () => {
    setPfxError("");
    setPfxReady(false);
    if (keyNeedsPassword && !keyPassword) {
      setPfxError("Ingresá la contraseña de la llave privada.");
      return;
    }
    setPfxBuilding(true);
    try {
      const bytes = await buildPfx({
        certificatePem: pem,
        privateKeyPem: hasKey ? privateKey!.pem : undefined,
        keyPassword: keyNeedsPassword ? keyPassword : undefined,
        pfxPassword,
      });
      triggerDownload(new Blob([bytes], { type: "application/x-pkcs12" }), getExportFilename());
      setPfxReady(true);
    } catch (e) {
      setPfxError(
        e instanceof Error ? e.message : "No se pudo generar el archivo .pfx."
      );
    } finally {
      setPfxBuilding(false);
    }
  };

  const handleDownload = async () => {
    if (exportMode === "pfx") {
      await handlePfxDownload();
      return;
    }
    const content = getExportContent();
    if (!content) return;
    triggerDownload(
      new Blob([content], { type: "application/x-pem-file" }),
      getExportFilename()
    );
  };

  const pfxSummary = (): string => {
    const lines = [
      "Archivo binario .pfx (PKCS#12) — se genera al presionar el botón.",
      "",
      `Contenido: ${hasKey ? "certificado + llave privada" : "solo certificado"}`,
      "Llave protegida con PBES2 (AES-256-CBC, PBKDF2)",
      "Verificación MAC: HMAC-SHA1 (PKCS#12)",
      pfxPassword
        ? "Contraseña del .pfx: definida (se pedirá al abrirlo)"
        : "Contraseña del .pfx: ninguna",
      "",
      pfxReady
        ? "Listo: se descargó el archivo."
        : "Presioná «Descargar .pfx» para generar y guardar el archivo.",
    ];
    return lines.join("\n");
  };

  const exportLabel =
    exportMode === "cert"
      ? "Certificado (.pem)"
      : exportMode === "key"
        ? "Llave privada (.pem)"
        : exportMode === "bundle"
          ? "Certificado + llave (.pem)"
          : "Archivo .pfx (PKCS#12)";

  const modeButton = (mode: ExportMode, label: string, icon: ReactNode, aria: string) => (
    <button
      onClick={() => selectMode(mode)}
      className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
        exportMode === mode
          ? "bg-primary text-primary-foreground"
          : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
      }`}
      aria-label={aria}
    >
      {icon}
      {label}
    </button>
  );

  const passwordInput = (
    value: string,
    onChange: (v: string) => void,
    placeholder: string
  ) => (
    <input
      type="password"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="mt-1 w-full rounded-md border border-input bg-background px-2.5 py-1.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
    />
  );

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">
        PEM original
      </h3>

      {/* Export mode selector */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {modeButton("cert", "Certificado", <FileDown className="w-3.5 h-3.5" />, "Exportar certificado")}
        <button
          onClick={() => selectMode("key")}
          disabled={!canExportKey}
          className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
            exportMode === "key"
              ? "bg-primary text-primary-foreground"
              : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
          }`}
          aria-label="Exportar llave privada"
        >
          <KeyRound className="w-3.5 h-3.5" />
          Llave
        </button>
        {modeButton("bundle", "Cert + Llave", <Package className="w-3.5 h-3.5" />, "Exportar certificado y llave juntos")}
        {modeButton("pfx", "PFX (.pfx)", <Lock className="w-3.5 h-3.5" />, "Exportar como archivo PFX")}
      </div>

      {exportMode === "key" && !canExportKey && (
        <p className="mb-2 text-xs text-muted-foreground">
          {hasKey
            ? "La llave está cifrada con contraseña. No se puede exportar en claro."
            : "No hay una llave privada cargada."}
        </p>
      )}

      {exportMode === "bundle" && (
        <p className="mb-2 text-xs text-muted-foreground">
          {canExportKey
            ? "Llave privada + certificado en un solo archivo .pem. Compatible con HAProxy, Nginx, Apache y otros servidores TLS."
            : "Sin llave privada — solo se exporta el certificado. Sube la llave para generar el archivo completo."}
        </p>
      )}

      {exportMode === "pfx" && (
        <div className="mb-3 space-y-2">
          <label className="block text-xs font-medium text-muted-foreground">
            Contraseña del .pfx (opcional)
            {passwordInput(
              pfxPassword,
              (v) => {
                setPfxPassword(v);
                setPfxError("");
              },
              "Sin contraseña"
            )}
          </label>
          {keyNeedsPassword && (
            <label className="block text-xs font-medium text-muted-foreground">
              Contraseña de la llave privada
              {passwordInput(
                keyPassword,
                (v) => {
                  setKeyPassword(v);
                  setPfxError("");
                },
                "Contraseña con la que se guardó la llave"
              )}
            </label>
          )}
          {!hasKey && (
            <p className="text-xs text-muted-foreground">
              Sin llave privada cargada: el .pfx contendrá solo el certificado.
            </p>
          )}
          {keyMismatch && (
            <p className="text-xs text-amber-600">
              La llave privada no corresponde a este certificado: el .pfx puede no
              ser útil en algunos servidores.
            </p>
          )}
          {pfxError && <p className="text-xs text-destructive">{pfxError}</p>}
        </div>
      )}

      <div className="overflow-x-auto max-h-60 overflow-y-auto">
        <pre className="text-xs monospace whitespace-pre-wrap text-foreground leading-relaxed">
          {exportMode === "pfx" ? pfxSummary() : getExportContent() || "—"}
        </pre>
      </div>

      <div className="mt-3 flex gap-2">
        <button
          onClick={handleCopy}
          className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-primary/5 px-3 py-2 text-sm text-primary hover:bg-primary/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          disabled={exportMode === "pfx" || !getExportContent()}
          aria-label="Copiar PEM"
        >
          <Copy className="w-4 h-4" />
          {showCopy ? "¡Copiado!" : "Copiar"}
        </button>
        <button
          onClick={handleDownload}
          className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-primary/5 px-3 py-2 text-sm text-primary hover:bg-primary/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          disabled={pfxBuilding || (exportMode !== "pfx" && !getExportContent())}
          aria-label={exportMode === "pfx" ? "Descargar archivo PFX" : "Descargar PEM"}
        >
          <Download className="w-4 h-4" />
          {pfxBuilding ? "Generando…" : exportMode === "pfx" ? "Descargar .pfx" : "Descargar .pem"}
        </button>
      </div>

      <p className="mt-2 text-xs text-muted-foreground text-center">
        {exportLabel}
      </p>
    </div>
  );
}
