import { KeyRound, ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import type { PrivateKeyInfo } from "../lib/certificate-parser";

interface KeyInfoProps {
  privateKey: PrivateKeyInfo | null;
}

export function KeyInfo({ privateKey }: KeyInfoProps) {
  if (!privateKey) return null;

  const matchIcon =
    privateKey.matchesCertificate === true ? (
      <ShieldCheck className="w-4 h-4 text-green-500" />
    ) : privateKey.matchesCertificate === false ? (
      <ShieldAlert className="w-4 h-4 text-red-500" />
    ) : (
      <ShieldQuestion className="w-4 h-4 text-yellow-500" />
    );

  const matchText =
    privateKey.matchesCertificate === true
      ? "Coincide con el certificado"
      : privateKey.matchesCertificate === false
        ? "No coincide con el certificado"
        : privateKey.encrypted
          ? "Cifrada — no se pudo verificar"
          : "No verificada";

  const formatLabel =
    privateKey.format === "pkcs1"
      ? "PKCS#1"
      : privateKey.format === "pkcs8"
        ? "PKCS#8"
        : privateKey.format === "pkcs8-encrypted"
          ? "PKCS#8 cifrado"
          : privateKey.format === "pkcs1-encrypted"
            ? "PKCS#1 cifrado"
            : "Desconocido";

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <div className="flex items-center gap-2 mb-3">
        <KeyRound className="w-4 h-4 text-muted-foreground" />
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Llave privada
        </h3>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span className="text-xs text-muted-foreground">Algoritmo</span>
          <p className="mt-1 font-medium">{privateKey.algorithm}</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Formato</span>
          <p className="mt-1">{formatLabel}</p>
        </div>
        {privateKey.size && (
          <div>
            <span className="text-xs text-muted-foreground">Tamaño</span>
            <p className="mt-1">{privateKey.size} bits</p>
          </div>
        )}
        {privateKey.curve && (
          <div>
            <span className="text-xs text-muted-foreground">Curva</span>
            <p className="mt-1">{privateKey.curve}</p>
          </div>
        )}
        <div>
          <span className="text-xs text-muted-foreground">Estado</span>
          <p className="mt-1">{privateKey.encrypted ? "Cifrada" : "Sin cifrar"}</p>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-border/20 flex items-center gap-2">
        {matchIcon}
        <span className="text-xs font-medium">{matchText}</span>
      </div>
    </div>
  );
}
