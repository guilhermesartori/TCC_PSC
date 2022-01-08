package br.ufsc.tsp;

import java.io.IOException;
import java.util.HashMap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;
import br.ufsc.tsp.service.KNetCommunicationService;

// TODO converter coisas pra lombok
@SpringBootApplication
public class TspApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(TspApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoderBean() {
		return new BCryptPasswordEncoder();
	}

	// TODO remove this
	public KNetCommunicationService keyManagerBean() throws KNetException {
		final var props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
		var parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");

		new KNetRequester(KkmipClientBuilder.build(null, null, parameters), parameters.get("USERNAME"),
				parameters.get("PW"));

		return new KNetCommunicationService();
	}

}
