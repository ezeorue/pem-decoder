import { File, KeyRound } from "lucide-react";
import type { PrivateKeyInfo } from "../lib/certificate-parser";

interface CertificateInputProps {
  pem: string;
  setPem: (value: string) => void;
  setCertificateData: (data: ArrayBuffer) => Promise<void>;
  setPrivateKeyData: (data: ArrayBuffer | string) => void;
  clearCertificate: () => void;
  clearPrivateKey: () => void;
  parseCertificate: () => Promise<void>;
  privateKey: PrivateKeyInfo | null;
  error: string | null;
  keyError: string | null;
  isValid: boolean;
  loading: boolean;
}

export function CertificateInput({
  pem,
  setPem,
  setCertificateData,
  setPrivateKeyData,
  clearCertificate,
  clearPrivateKey,
  parseCertificate,
  privateKey,
  error,
  keyError,
  isValid,
  loading,
}: CertificateInputProps) {
  const handleInput = (event: React.FormEvent<HTMLTextAreaElement>) => {
    setPem(event.currentTarget.value);
  };

  const handleCertFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result;
      if (result instanceof ArrayBuffer) {
        void setCertificateData(result);
      }
    };
    reader.readAsArrayBuffer(file);
    event.target.value = "";
  };

  const handleKeyFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result;
      if (result instanceof ArrayBuffer) {
        setPrivateKeyData(result);
      }
    };
    reader.readAsArrayBuffer(file);
    event.target.value = "";
  };

  return (
    <div className="space-y-4 rounded-lg bg-card border border-border p-5">
      <div className="border-b border-border pb-3">
        <h2 className="text-lg font-semibold text-brand-oscuro">Certificado</h2>
      </div>

      {/* Paste Certificate */}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          Pegar certificado
        </h3>
        <textarea
          placeholder={
            "-----BEGIN CERTIFICATE-----\nMIID...\n...\n-----END CERTIFICATE-----"
          }
          value={pem}
          onInput={handleInput}
          className="w-full rounded-md border border-border bg-background px-4 py-3 resize-y text-sm monospace focus:ring-2 focus:ring-ring focus:border-transparent"
          rows={8}
          aria-label="Texto del certificado PEM"
        />
        <div className="mt-2 flex justify-between text-xs text-muted-foreground">
          <span>Caracteres: {pem.length}</span>
          <button
            onClick={clearCertificate}
            className="hover:text-destructive transition-colors underline underline-offset-2"
            aria-label="Limpiar certificado"
          >
            Limpiar
          </button>
        </div>
      </div>

      {/* Upload certificate file */}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          Subir certificado
        </h3>
        <div className="border-2 border-dashed border-border rounded-md p-6 text-center hover:border-ring transition-colors">
          <File className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-sm text-muted-foreground mb-1">
            Arrastra tu certificado aquí
          </p>
          <p className="text-xs text-muted-foreground mb-2">o</p>
          <input
            type="file"
            accept=".pem,.crt,.cer,.cert,.der,.p7b,.p7c"
            onChange={handleCertFileSelect}
            className="hidden"
            id="cert-upload"
          />
          <label
            htmlFor="cert-upload"
            className="inline-block cursor-pointer rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Examinar archivos
          </label>
          <p className="text-xs text-muted-foreground mt-2">
            .pem, .crt, .cer, .cert, .der, .p7b
          </p>
        </div>
      </div>

      {/* Upload private key */}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
          Llave privada (opcional)
        </h3>
        <div className="border-2 border-dashed border-border rounded-md p-4 text-center hover:border-ring transition-colors">
          <KeyRound className="w-6 h-6 text-muted-foreground mx-auto mb-1" />
          {privateKey ? (
            <div className="text-sm">
              <p className="text-foreground font-medium">
                {privateKey.algorithm}
                {privateKey.size ? ` ${privateKey.size}` : ""}
                {privateKey.curve ? ` (${privateKey.curve})` : ""}
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {privateKey.encrypted
                  ? "Cifrada con contraseña"
                  : privateKey.format === "pkcs1"
                    ? "PKCS#1"
                    : "PKCS#8"}
                {privateKey.matchesCertificate === true && " • ✓ Coincide con el certificado"}
                {privateKey.matchesCertificate === false && " • ✗ No coincide con el certificado"}
              </p>
              <button
                onClick={clearPrivateKey}
                className="mt-1 text-xs text-destructive hover:underline"
                aria-label="Quitar llave privada"
              >
                Quitar llave
              </button>
            </div>
          ) : (
            <>
              <p className="text-sm text-muted-foreground mb-1">
                Sube tu llave privada .key
              </p>
              <input
                type="file"
                accept=".key,.pem,.pk8,.der"
                onChange={handleKeyFileSelect}
                className="hidden"
                id="key-upload"
              />
              <label
                htmlFor="key-upload"
                className="inline-block cursor-pointer rounded-md bg-secondary px-3 py-1.5 text-sm text-secondary-foreground hover:bg-secondary/80 transition-colors"
              >
                Examinar llave
              </label>
              <p className="text-xs text-muted-foreground mt-1">
                .key, .pem, .der
              </p>
            </>
          )}
        </div>
        {keyError && (
          <div
            role="alert"
            className="mt-2 p-2 rounded-md bg-destructive/10 text-destructive text-xs border border-destructive/20"
          >
            {keyError}
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="p-3 rounded-md bg-destructive/10 text-destructive text-sm border border-destructive/20 whitespace-pre-wrap"
        >
          {error}
        </div>
      )}

      {/* Decode Button */}
      <button
        onClick={() => void parseCertificate()}
        disabled={!pem.trim() || loading}
        className="w-full rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        aria-label="Decodificar certificado"
      >
        {loading ? "Decodificando…" : "Decodificar certificado"}
      </button>

      {/* Success indicator */}
      {isValid && !error && (
        <div
          role="status"
          className="p-3 rounded-md bg-green-500/10 text-green-700 dark:text-green-400 text-sm font-medium border border-green-500/20"
        >
          Certificado decodificado correctamente
        </div>
      )}
    </div>
  );
}
