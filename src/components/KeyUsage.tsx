import { DecodedCertificate } from "../lib/certificate-parser";

interface KeyUsageProps {
  certificate: DecodedCertificate | null;
}

export function KeyUsage({ certificate }: KeyUsageProps) {
  if (!certificate) return null;

  const { keyUsage } = certificate;

  if (!keyUsage.length) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">Uso de clave</h3>
      <div className="flex flex-wrap gap-2">
        {keyUsage.map((usage, index) => (
          <span
            key={index}
            className="inline-flex items-center rounded-md border border-border px-2.5 py-1.5 text-sm font-medium text-foreground"
          >
            {[usage]}
          </span>
        ))}
      </div>
    </div>
  );
}
