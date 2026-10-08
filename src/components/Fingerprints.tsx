import { DecodedCertificate } from "../lib/certificate-parser";

interface FingerprintsProps {
  certificate: DecodedCertificate | null;
}

export function Fingerprints({ certificate }: FingerprintsProps) {
  if (!certificate) return null;

  const { fingerprints } = certificate;

  if (!fingerprints?.sha256 && !fingerprints?.sha1 && !fingerprints?.md5) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">
        Huellas digitales
      </h3>
      <div className="space-y-2">
        {fingerprints.sha256 && (
          <div className="flex items-baseline gap-2">
            <span className="w-2 h-2 rounded-md bg-accent/40 flex-shrink-0"></span>
            <span className="text-sm font-medium">SHA-256</span>
            <span className="ml-auto flex-1 truncate">{fingerprints.sha256}</span>
            <button
              onClick={() => navigator.clipboard.writeText(fingerprints.sha256!)}
              className="text-muted-foreground hover:text-foreground transition-colors text-xs"
              aria-label="Copiar huella digital SHA-256"
            >
              [Copiar]
            </button>
          </div>
        )}

        {fingerprints.sha1 && (
          <div className="flex items-baseline gap-2">
            <span className="w-2 h-2 rounded-md bg-accent/40 flex-shrink-0"></span>
            <span className="text-sm font-medium">SHA-1</span>
            <span className="ml-auto flex-1 truncate">{fingerprints.sha1}</span>
            <button
              onClick={() => navigator.clipboard.writeText(fingerprints.sha1!)}
              className="text-muted-foreground hover:text-foreground transition-colors text-xs"
              aria-label="Copiar huella digital SHA-1"
            >
              [Copiar]
            </button>
          </div>
        )}

        {fingerprints.md5 && (
          <div className="flex items-baseline gap-2">
            <span className="w-2 h-2 rounded-md bg-accent/40 flex-shrink-0"></span>
            <span className="text-sm font-medium">MD5</span>
            <span className="ml-auto flex-1 truncate">{fingerprints.md5}</span>
            <button
              onClick={() => navigator.clipboard.writeText(fingerprints.md5!)}
              className="text-muted-foreground hover:text-foreground transition-colors text-xs"
              aria-label="Copiar huella digital MD5"
            >
              [Copiar]
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
