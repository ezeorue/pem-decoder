import { DecodedCertificate } from "../lib/certificate-parser";

interface SANListProps {
  certificate: DecodedCertificate | null;
}

export function SANList({ certificate }: SANListProps) {
  if (!certificate) return null;

  const { subjectAlternativeNames } = certificate;

  if (!subjectAlternativeNames.length) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">
        Nombres alternativos del sujeto
      </h3>
      <div className="space-y-1 max-h-40 overflow-y-auto">
        {subjectAlternativeNames.map((san, index) => (
          <div
            key={index}
            className="flex items-baseline gap-1 text-sm select-none"
          >
            <span className="w-2 h-2 rounded-md bg-accent/40 flex-shrink-0"></span>
            <span className="text-foreground">
              {san.type === "DNS" ? "DNS:" : san.type === "IP" ? "IP:" : "Otro:"} {san.value}
            </span>
          </div>
        ))}
      </div>

      {subjectAlternativeNames.length > 1 && (
        <p className="mt-1 text-xs text-muted-foreground">
          {subjectAlternativeNames.length} nombres
        </p>
      )}
    </div>
  );
}
