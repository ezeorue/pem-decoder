import { DecodedCertificate } from "../lib/certificate-parser";

interface SubjectProps {
  certificate: DecodedCertificate | null;
}

export function Subject({ certificate }: SubjectProps) {
  if (!certificate) return null;

  const { subject } = certificate;

  const fields = [
    { label: "Nombre común (CN)", value: subject.commonName },
    { label: "Organización (O)", value: subject.organization },
    { label: "Unidad organizacional (OU)", value: subject.organizationalUnit },
    { label: "País (C)", value: subject.country },
    { label: "Estado (ST)", value: subject.state },
    { label: "Localidad (L)", value: subject.locality },
    { label: "Correo electrónico", value: subject.email },
  ];

  const presentFields = fields.filter((f) => f.value);

  if (presentFields.length === 0) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">Sujeto</h3>
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
