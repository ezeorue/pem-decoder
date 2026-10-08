export function SecurityNotice() {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3">
      <p className="text-xs text-muted-foreground">
        Esta herramienta procesa certificados completamente en tu navegador.
        El contenido no se transmite a ningún servidor, no se almacena y no
        utiliza API externas.
      </p>
    </div>
  );
}
