import type { DecodedCertificate } from "../lib/certificate-parser";

interface ValidityProps {
  certificate: DecodedCertificate | null;
}

export function Validity({ certificate }: ValidityProps) {
  if (!certificate) return null;

  const { validity } = certificate;
  const { notBefore, notAfter, daysRemaining, status } = validity;

  const durationDays = Math.ceil(
    (notAfter.getTime() - notBefore.getTime()) / (1000 * 60 * 60 * 24)
  );

  const percentRemaining =
    durationDays > 0
      ? Math.max(0, Math.min(100, (daysRemaining / durationDays) * 100))
      : 0;

  const statusClass =
    status === "valid"
      ? "bg-green-50 text-green-700 border-green-200"
      : status === "expiring-soon"
        ? "bg-yellow-50 text-yellow-700 border-yellow-200"
        : "bg-red-50 text-red-700 border-red-200";

  const barClass =
    status === "valid"
      ? "bg-green-500"
      : status === "expiring-soon"
        ? "bg-yellow-500"
        : "bg-red-500";

  const statusLabel =
    status === "valid"
      ? "Válido"
      : status === "expiring-soon"
        ? "Por vencer"
        : "Vencido";

  const dateFormat: Intl.DateTimeFormatOptions = {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  };

  return (
    <div className="rounded-lg bg-card border border-border p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Vigencia
        </h3>
        <span
          className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${statusClass}`}
        >
          {statusLabel}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <span className="text-xs text-muted-foreground">Válido desde</span>
          <p className="mt-0.5 text-sm">
            {notBefore.toLocaleDateString("es-ES", dateFormat)}
          </p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Válido hasta</span>
          <p className="mt-0.5 text-sm">
            {notAfter.toLocaleDateString("es-ES", dateFormat)}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <span className="text-xs text-muted-foreground">Duración</span>
          <p className="mt-0.5 text-sm">{durationDays} días</p>
        </div>
        <div>
          <span className="text-xs text-muted-foreground">Días restantes</span>
          <p className="mt-0.5 text-sm font-medium">
            {daysRemaining > 0 ? daysRemaining : 0}
          </p>
        </div>
      </div>

      <div>
        <div className="h-1.5 rounded bg-muted overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${barClass}`}
            style={{ width: `${percentRemaining}%` }}
          />
        </div>
        <div className="flex justify-between mt-1 text-[0.7rem] text-muted-foreground">
          <span>Vencido</span>
          <span>{Math.round(percentRemaining)}% restante</span>
        </div>
      </div>
    </div>
  );
}
