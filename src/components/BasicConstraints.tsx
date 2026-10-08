import { DecodedCertificate } from "../lib/certificate-parser";

interface BasicConstraintsProps {
  certificate: DecodedCertificate | null;
}

export function BasicConstraints({ certificate }: BasicConstraintsProps) {
  if (!certificate) return null;

  const { basicConstraints } = certificate;

  if (!basicConstraints) return null;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-3">
        Restricciones básicas
      </h3>
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <span className="text-muted-foreground">CA</span>
          <p>{basicConstraints.ca ? "Sí" : "No"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Longitud de ruta</span>
          <p>{basicConstraints.pathLength !== undefined ? basicConstraints.pathLength : "N/D"}</p>
        </div>
      </div>
    </div>
  );
}
