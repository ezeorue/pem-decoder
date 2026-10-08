import { useState, useEffect } from "react";
import { Lock, Moon, Sun, Monitor } from "lucide-react";

type Theme = "system" | "light" | "dark";

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") {
    root.classList.add("dark");
  } else if (theme === "light") {
    root.classList.remove("dark");
  } else {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.classList.toggle("dark", prefersDark);
  }
}

export function Header() {
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const cycleTheme = () => {
    setTheme((prev) => {
      if (prev === "system") return "light";
      if (prev === "light") return "dark";
      return "system";
    });
  };

  const label = theme === "system" ? "Sistema" : theme === "light" ? "Claro" : "Oscuro";
  const Icon = theme === "system" ? Monitor : theme === "light" ? Sun : Moon;

  return (
    <header className="bg-brand-oscuro">
      <div className="max-w-6xl mx-auto px-5 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-brand-azul flex items-center justify-center">
            <Lock className="w-4.5 h-4.5 text-white" strokeWidth={2.5} aria-hidden="true" />
          </div>
          <div className="leading-tight">
            <h1 className="text-[0.95rem] font-semibold text-white">
              Decodificador PEM
            </h1>
            <p className="text-[0.7rem] text-white/50">
              Certificados SSL/TLS
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <span className="text-[0.7rem] text-white/40 hidden sm:inline">
            Procesamiento local
          </span>
          <button
            onClick={cycleTheme}
            className="inline-flex items-center gap-1.5 rounded border border-white/15 px-2.5 py-1 text-xs text-white/70 hover:text-white hover:border-white/30 transition-colors"
            aria-label={`Tema: ${label}. Haz clic para cambiar.`}
          >
            <Icon className="w-3.5 h-3.5" aria-hidden="true" />
            {label}
          </button>
        </div>
      </div>
    </header>
  );
}
