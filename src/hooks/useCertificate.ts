import { useState, useCallback } from "react";
import {
  parseCertificate,
  parsePrivateKey,
  fileToPem,
  verifyKeyMatch,
  type DecodedCertificate,
  type PrivateKeyInfo,
} from "../lib/certificate-parser";

export interface UseCertificateReturn {
  certificate: DecodedCertificate | null;
  privateKey: PrivateKeyInfo | null;
  pem: string;
  setPem: (value: string) => void;
  setCertificateData: (data: ArrayBuffer) => Promise<void>;
  setPrivateKeyData: (data: ArrayBuffer | string) => void;
  clearCertificate: () => void;
  clearPrivateKey: () => void;
  isValid: boolean;
  error: string | null;
  keyError: string | null;
  loading: boolean;
  parseCertificate: () => Promise<void>;
}

export function useCertificate(): UseCertificateReturn {
  const [pem, setPemState] = useState("");
  const [certificate, setCertificate] = useState<DecodedCertificate | null>(null);
  const [privateKey, setPrivateKey] = useState<PrivateKeyInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const setPem = useCallback((value: string) => {
    setPemState(value);
    setError(null);
    setCertificate(null);
  }, []);

  /** Handle raw file bytes (PEM text or DER binary) for the certificate. */
  const setCertificateData = useCallback(
    async (data: ArrayBuffer) => {
      setLoading(true);
      setError(null);
      setCertificate(null);
      try {
        const pemText = fileToPem(data);
        if (!pemText) {
          setError(
            "Formato de archivo no reconocido. Se aceptan formatos PEM, DER (.cer, .der) y PKCS#7."
          );
          return;
        }
        setPemState(pemText);
        const parsed = await parseCertificate(pemText);
        if (!parsed) {
          setError(
            "No se pudo decodificar este certificado.\n\nEl formato del archivo parece correcto, pero el certificado X.509 no pudo ser analizado."
          );
          return;
        }
        setCertificate(parsed);

        // Re-verify private key match if one is loaded
        if (privateKey && !privateKey.encrypted) {
          const match = await verifyKeyMatch(privateKey.pem, pemText);
          setPrivateKey((prev) => (prev ? { ...prev, matchesCertificate: match } : prev));
        }
      } catch (err) {
        setError("Este formato de certificado no es compatible.");
        console.error("Certificate parsing error:", err);
      } finally {
        setLoading(false);
      }
    },
    [privateKey]
  );

  /** Handle raw private key bytes (PEM text or DER binary). */
  const setPrivateKeyData = useCallback(
    (data: ArrayBuffer | string) => {
      setKeyError(null);
      try {
        const info = parsePrivateKey(data);
        if (!info) {
          setKeyError(
            "Formato de llave privada no reconocido. Se aceptan formatos PEM y DER (.key, .pem)."
          );
          setPrivateKey(null);
          return;
        }
        setPrivateKey(info);

        // If cert is loaded, verify match asynchronously
        if (certificate && !info.encrypted) {
          void verifyKeyMatch(info.pem, certificate.pem).then((match) => {
            setPrivateKey((prev) => (prev ? { ...prev, matchesCertificate: match } : prev));
          });
        }
      } catch (err) {
        setKeyError("No se pudo leer la llave privada.");
        console.error("Private key parsing error:", err);
      }
    },
    [certificate]
  );

  const clearCertificate = useCallback(() => {
    setPemState("");
    setCertificate(null);
    setError(null);
    setLoading(false);
    // Re-check key match when cert is removed
    setPrivateKey((prev) => (prev ? { ...prev, matchesCertificate: null } : prev));
  }, []);

  const clearPrivateKey = useCallback(() => {
    setPrivateKey(null);
    setKeyError(null);
  }, []);

  const parseCertificateFromPem = useCallback(async () => {
    if (!pem.trim()) {
      setError("Por favor pega o sube un certificado.");
      return;
    }

    if (
      !pem.includes("-----BEGIN CERTIFICATE-----") ||
      !pem.includes("-----END CERTIFICATE-----")
    ) {
      setError(
        "Certificado PEM inválido.\n\nAsegúrate de que el certificado contenga:\n-----BEGIN CERTIFICATE-----\ny\n-----END CERTIFICATE-----"
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const parsed = await parseCertificate(pem);
      if (!parsed) {
        setError(
          "No se pudo decodificar este certificado.\n\nEl formato PEM parece ser correcto, pero el certificado X.509 no pudo ser analizado."
        );
        return;
      }
      setCertificate(parsed);

      // Re-verify private key match
      if (privateKey && !privateKey.encrypted) {
        const match = await verifyKeyMatch(privateKey.pem, pem);
        setPrivateKey((prev) => (prev ? { ...prev, matchesCertificate: match } : prev));
      }
    } catch (err) {
      setError("Este formato de certificado no es compatible.");
      console.error("Certificate parsing error:", err);
    } finally {
      setLoading(false);
    }
  }, [pem, privateKey]);

  return {
    certificate,
    privateKey,
    pem,
    setPem,
    setCertificateData,
    setPrivateKeyData,
    clearCertificate,
    clearPrivateKey,
    isValid: certificate !== null,
    error,
    keyError,
    loading,
    parseCertificate: parseCertificateFromPem,
  };
}
