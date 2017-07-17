package br.gov.serpro.cert;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertitficateHelper {

	private static final Logger log = LoggerFactory.getLogger(CertitficateHelper.class);

	public static final String APP_CONF_DIR = System.getProperty("user.home") + File.separator + "test-cert"; // System.getProperty("java.io.tmpdir");

	public static final Path CA_CERT_PATH = Paths.get(APP_CONF_DIR, "ca.cer");
	public static final Path CA_KEYSTORE_PATH = Paths.get(APP_CONF_DIR, "ca.p12");

	public static final Path HOST_CERT_PATH = Paths.get(APP_CONF_DIR, "host.cer");
	public static final Path HOST_KEYSTORE_PATH = Paths.get(APP_CONF_DIR, "host.p12");

	public static final char[] PASS = "changeit".toCharArray();

	public static final String KEYSTORE_TYPE = "PKCS12";

	public static void initializeSSLCertificate() throws NoSuchAlgorithmException, NoSuchProviderException,
			CertIOException, OperatorCreationException, CertificateException, KeyStoreException, IOException,
			InvalidKeyException, UnrecoverableKeyException, SignatureException {

		File certDir = new File(APP_CONF_DIR);

		if (!certDir.exists()) {
			certDir.mkdirs();
		}

		log.info("Certificates Directory: " + APP_CONF_DIR);

		File fileCertCa = new File(CA_CERT_PATH.toString());

		if (!Files.exists(CA_CERT_PATH)) {

			// ============ 1 - Criar certificados ============
			Authority authority = new Authority();

			log.info("Creating CA...");
			KeyStore keyStore = CertificateCreator.createRootCertificate(authority, KEYSTORE_TYPE);

			fileCertCa = new File(CA_CERT_PATH.toString());
			FileOutputStream fosCertCa = new FileOutputStream(fileCertCa);
			fosCertCa.write(keyStore.getCertificate(authority.alias()).getEncoded());
			fosCertCa.close();

			keyStore.store(new FileOutputStream(CA_KEYSTORE_PATH.toString()), PASS);

			log.info("Creating localhost (127.0.0.1) certificate...");
			KeyStore keyStore2 = CertificateCreator.createServerCertificate("serpro.gov.br",
					new SubjectAlternativeNameHolder(), authority, keyStore.getCertificate(authority.alias()),
					(PrivateKey) keyStore.getKey(authority.alias(), PASS));

			keyStore2.store(new FileOutputStream(HOST_KEYSTORE_PATH.toString()), PASS);

			FileOutputStream f2 = new FileOutputStream(new File(HOST_CERT_PATH.toString()));
			f2.write(keyStore2.getCertificate(authority.alias()).getEncoded());
			f2.close();

		}

	}

}
