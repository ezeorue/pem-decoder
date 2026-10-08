# Decodificador PEM

Aplicación web para decodificar certificados SSL/TLS en formato **PEM, DER, CRT y PKCS#7 (.p7b)**, con vista completa de:

- Sujeto, emisor, vigencia y huellas digitales (SHA-1 / SHA-256 / SHA-512)
- Extensiones: Basic Constraints, Key Usage, Extended Key Usage, SAN
- Carga de **llave privada** con detección de formato (PKCS#8/PKCS#1/SEC1, cifrada o no) y verificación de correspondencia con el certificado
- Exportaciones: certificado `.pem`, llave `.pem`, bundle (cert + llave) y **archivo `.pfx` (PKCS#12)** con o sin contraseña, generado en el navegador
- **Procesamiento 100% local**: ningún archivo sale del navegador

Stack: **Vite + React 19 + TypeScript + Tailwind CSS 3**, `@peculiar/x509` / `@peculiar/asn1-*` para ASN.1 y WebCrypto para el cifrado.

## Desarrollo local

Requisitos: Node.js 20.19+ / 22+ / 24.

```bash
npm install        # instalar dependencias
npm run dev        # servidor de desarrollo (http://localhost:5173)
npm run lint       # linter (oxlint)
npm run build      # type-check + build de producción en dist/
npm run preview    # servir dist/ en local
```

Tests de verificación del generador PFX (requieren fixtures generadas con OpenSSL):

```bash
node scripts/pfx-smoke.ts
```

---

## Docker: generar la imagen

La imagen es **multi-etapa** y queda reducida a un nginx estático:

| Archivo | Rol |
|---|---|
| `Dockerfile` | Etapa 1 `node:24-alpine`: `npm ci` + `npm run build` → `dist/`. Etapa 2 `nginxinc/nginx-unprivileged`: sirve `dist/` como usuario no-root en el **puerto 8080** |
| `nginx.conf` | SPA fallback, `/healthz`, gzip, cache por tipo de archivo y cabeceras de seguridad (CSP, `nosniff`, etc.) |
| `.dockerignore` | Excluye `node_modules`, `dist`, `.git`, `scripts/` — el contexto de build queda liviano y el build es reproducible (`npm ci` + lockfile) |

### Build

```bash
docker build -t pem-decoder:latest .
```

### Probar en local

```bash
docker run --rm -p 8080:8080 --name pem-decoder pem-decoder:latest
```

- App: http://localhost:8080
- Sonda de salud: http://localhost:8080/healthz → `ok`

---

## Subir la imagen a Quay.io (Red Hat)

1. **Crear el repositorio** en [quay.io](https://quay.io): *Create New Repository* → nombre `pem-decoder`, visibilidad pública o privada.
2. **Login**:

   ```bash
   docker login quay.io
   ```

3. **Etiquetar** (reemplazá `<usuario>` por tu usuario/org de Quay):

   ```bash
   docker tag pem-decoder:latest quay.io/<usuario>/pem-decoder:latest
   docker tag pem-decoder:latest quay.io/<usuario>/pem-decoder:1.0.0
   ```

4. **Push**:

   ```bash
   docker push quay.io/<usuario>/pem-decoder:latest
   docker push quay.io/<usuario>/pem-decoder:1.0.0
   ```

5. Verificar en `https://quay.io/repository/<usuario>/pem-decoder`.

### Imagen multi-arquitectura (opcional)

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t quay.io/<usuario>/pem-decoder:1.0.0 --push .
```

---

## ¿La app está pensada para vivir en un contenedor?

**Sí: es un caso de uso ideal.** La app es una SPA puramente estática sin servidor propio, y toda la lógica pesada (ASN.1, descifrado de llaves, WebCrypto) corre en el navegador del usuario, no en el proceso del contenedor.

### Lo que ya juega a favor

- **Sin estado ni sesiones**: el contenedor solo sirve archivos de `dist/`; cualquier réplica responde igual → escalado horizontal trivial y pods intercambiables.
- **Sin secretos ni datos sensibles en el contenedor**: los certificados y llaves privadas se procesan en el navegador y nunca tocan el pod; no hay credenciales que inyectar ni volumes que montar.
- **Un solo puerto TCP** (8080) y **cero variables de entorno**: la configuración es inmutable — cada imagen = una versión exacta; despliegue y rollback se resuelven cambiando el tag en Quay.
- **Sin persistencia**: los pods pueden ser efímeros; no hay bases de datos ni archivos compartidos.
- **Build reproducible**: `npm ci` con `package-lock.json` en una etapa, artefacto final aislado del entorno de desarrollo.

### Ajustes ya incorporados en esta imagen

- **Usuario no-root** (`nginx-unprivileged`, UID 101) y **puerto 8080** → compatible con el SCC `restricted-v2` de OpenShift, sin privilegios ni puertos privilegiados.
- **`/healthz`** → listo para `livenessProbe`/`readinessProbe` (k8s/OpenShift) y `HEALTHCHECK` de Docker/Compose.
- **gzip + cache inteligente**: assets con hash cacheados 1 año, `index.html` siempre revalidado → sin HTML viejo tras un deploy.
- **Cabeceras de seguridad**: CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.

### Puntos de atención (no bloqueantes)

- **Primer load del cliente**: el bundle JS (~480 KB / ~135 KB gzip) se descarga al navegador en la primera visita; después de eso el cache lo resuelve.
- **Google Fonts**: la tipografía Inter se carga desde `fonts.googleapis.com` → el cluster necesita egress hacia ese dominio si querés la fuente exacta (si no, cae a la fuente del sistema; la CSP ya la permite). En entornos aislados convendría auto-alojar la fuente y quitar la dependencia externa.
- **Sin SSR/prerender**: el contenido se arma en el cliente; para una herramienta de uso personal/interno no es un problema.
- **TLS en el edge**: como la app manipula llaves privadas, servirla siempre detrás de un Ingress/Route con HTTPS (la CSP y headers ya asumen origin único).
- **Si en el futuro hubiera backend** (verificación OCSP/CRL, etc.), conviene mantenerlo en un servicio/imagen separado y no mezclarlo con este frontend.

### Ejemplo de despliegue en OpenShift

```bash
oc new-app quay.io/<usuario>/pem-decoder:1.0.0 --name=pem-decoder
oc expose service pem-decoder
# Sondas contra /healthz en el puerto 8080
```
