import { Header } from "./components/Header";
import { CertificateInput } from "./components/CertificateInput";
import { CertificateOverview } from "./components/CertificateOverview";
import { Subject } from "./components/Subject";
import { Issuer } from "./components/Issuer";
import { Validity } from "./components/Validity";
import { SANList } from "./components/SANList";
import { Fingerprints } from "./components/Fingerprints";
import { KeyUsage } from "./components/KeyUsage";
import { ExtendedKeyUsage } from "./components/ExtendedKeyUsage";
import { BasicConstraints } from "./components/BasicConstraints";
import { KeyInfo } from "./components/KeyInfo";
import { RawCertificate } from "./components/RawCertificate";
import { SecurityNotice } from "./components/SecurityNotice";
import { useCertificate } from "./hooks/useCertificate";

function App() {
  const cert = useCertificate();

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="max-w-6xl mx-auto px-5 py-6">
        <CertificateInput
          pem={cert.pem}
          setPem={cert.setPem}
          setCertificateData={cert.setCertificateData}
          setPrivateKeyData={cert.setPrivateKeyData}
          clearCertificate={cert.clearCertificate}
          clearPrivateKey={cert.clearPrivateKey}
          parseCertificate={cert.parseCertificate}
          privateKey={cert.privateKey}
          error={cert.error}
          keyError={cert.keyError}
          isValid={cert.isValid}
          loading={cert.loading}
        />

        {cert.certificate && (
          <>
            {/* Row 1: overview spans full width */}
            <div className="mt-5">
              <CertificateOverview certificate={cert.certificate} />
            </div>

            {/* Row 2: identity info */}
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Subject certificate={cert.certificate} />
              <Issuer certificate={cert.certificate} />
            </div>

            {/* Row 3: validity + SAN */}
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Validity certificate={cert.certificate} />
              <SANList certificate={cert.certificate} />
            </div>

            {/* Row 4: technical details */}
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <KeyUsage certificate={cert.certificate} />
              <ExtendedKeyUsage certificate={cert.certificate} />
              <BasicConstraints certificate={cert.certificate} />
            </div>

            {/* Row 5: fingerprints + key info */}
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Fingerprints certificate={cert.certificate} />
              <KeyInfo privateKey={cert.privateKey} />
            </div>

            {/* Row 6: raw PEM */}
            <div className="mt-4">
              <RawCertificate
                pem={cert.certificate.pem}
                privateKey={cert.privateKey}
              />
            </div>
          </>
        )}

        <div className="mt-5">
          <SecurityNotice />
        </div>
      </main>
    </div>
  );
}

export default App;
