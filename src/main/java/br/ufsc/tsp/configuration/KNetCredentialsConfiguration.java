package br.ufsc.tsp.configuration;

import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;

@Configuration
public class KNetCredentialsConfiguration {

	private static Map<String, String> knetParameters;

	static {
		knetParameters = new HashMap<String, String>();
		knetParameters.put("ADDRESS_CONN", "192.168.66.20");
		knetParameters.put("PORT_CONN", "60055");
		knetParameters.put("USERNAME", "test_user");
		knetParameters.put("PW", "2m;z#MkD-tcc-guilherme");
		knetParameters.put("MAX_CONNECTIONS", "1");
	}

	@Lazy
	@Bean
	public KNetRequester knetRequester() throws KNetException {
		var kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, knetParameters),
				knetParameters.get("USERNAME"), knetParameters.get("PW"));
		return kNetRequester;
	}

	public static void setParameters(Map<String, String> parameters) {
		knetParameters = parameters;
	}

}
