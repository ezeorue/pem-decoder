import type { DecodedCertificate } from "../lib/certificate-parser";

interface CertificateOverviewProps {
  certificate: DecodedCertificate | null;
}

const STATUS_LABELS: Record<string, string> = {
  valid: "VÁLIDO",
  "expiring-soon": "POR VENCER",
  expired: "VENCIDO",
};

export function CertificateOverview({ certificate }: CertificateOverviewProps) {
  if (!certificate) return null;

  const { validity, subject, issuer, serialNumber, version } = certificate;

  const statusClass =
    validity.status === "valid"
      ? "bg-green-50 text-green-700 border-green-200"
      : validity.status === "expiring-soon"
      ? "bg-yellow-50 text-yellow-700 border-yellow-200"
      : "bg-red-50 text-red-700 border-red-200";

  const statusDot =
    validity.status === "valid"
      ? "bg-green-500"
      : validity.status === "expiring-soon"
      ? "bg-yellow-500"
      : "bg-red-500";

  const statusLabel = STATUS_LABELS[validity.status] || validity.status;

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${statusDot}`} />
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Resumen</span>
        </div>
        <span
          className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${statusClass}`}
        >
          {statusLabel}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span className="text-muted-foreground">Nombre común</span>
          <p className="mt-1">{subject.commonName || "—"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Emisor</span>
          <p className="mt-1">{issuer.commonName || "—"}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Número de serie</span>
          <p className="mt-1 break-all">{serialNumber}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Versión</span>
          <p className="mt-1">{version}</p>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-border/20">
        <span className="text-xs text-muted-foreground">Válido desde</span>
        <p className="mt-1">{validity.notBefore.toLocaleDateString("es-ES")}</p>
        <span className="text-xs text-muted-foreground">Válido hasta</span>
        <p className="mt-1">{validity.notAfter.toLocaleDateString("es-ES")}</p>
        <span className="text-xs text-muted-foreground">Días restantes</span>
        <p className="mt-1">{validity.daysRemaining}</p>
      </div>
    </div>
  );
}
