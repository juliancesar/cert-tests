package br.gov.serpro.cert;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Hello world!
 *
 */
public class Main {

	private static final Logger log = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) {

		Security.addProvider(new BouncyCastleProvider());

		try {
			CertitficateHelper.initializeSSLCertificate();

		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	public static void test() {

		log.info("Iniciando...");

		Provider[] providers = Security.getProviders();

		for (Provider provider : providers) {

			log.info(provider.getName());

			for (Service service : provider.getServices()) {

				log.info("---" + service.getAlgorithm() + " / " + service.getType());

			}

		}
	}
}
