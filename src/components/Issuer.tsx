import { DecodedCertificate } from "../lib/certificate-parser";

interface IssuerProps {
  certificate: DecodedCertificate | null;
}

export function Issuer({ certificate }: IssuerProps) {
  if (!certificate) return null;

  const { issuer } = certificate;

  const fields = [
    { label: "Nombre común (CN)", value: issuer.commonName },
    { label: "Organización (O)", value: issuer.organization },
    { label: "Unidad organizacional (OU)", value: issuer.organizationalUnit },
    { label: "País (C)", value: issuer.country },
    { label: "Estado (ST)", value: issuer.state },
    { label: "Localidad (L)", value: issuer.locality },
  ];

  const presentFields = fields.filter((f) => f.value);

  if (presentFields.length === 0) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">Emisor</h3>
      <div className="space-y-1">
        {presentFields.map((field, index) => (
          <div key={index} className="flex items-baseline gap-2">
            <span className="w-2 h-2 rounded-md bg-accent/40 flex-shrink-0"></span>
            <span className="text-sm font-medium">{field.label}:</span>
            <span className="ml-auto text-foreground">{field.value || "—"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
