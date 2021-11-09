package br.ufsc.tsp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.utility.KeyManager;

@SpringBootApplication
public class TspApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(TspApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoderBean() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(AppUserService userService) {
		return args -> {
			userService.saveUser(new AppUser(null, "Guilherme Sartori", "guilherme", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Fulano de Tal", "fulano", "fulano", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Usuario Teste", "usuario", "passwordsenha", new ArrayList<>()));

			userService.addRoleToUser("guilherme", Authority.CREATE_KEY);
			userService.addRoleToUser("guilherme", Authority.DELETE_KEY);
			userService.addRoleToUser("usuario", Authority.CREATE_KEY);
			userService.addRoleToUser("usuario", Authority.DELETE_KEY);
			userService.addRoleToUser("fulano", Authority.CHANGE_AUTHORITY);
		};
	}

	@Bean
	public KeyManager keyManagerBean() throws KNetException {
		final Properties props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("ADDRESS_CONN", "192.168.66.20");
		parameters.put("PORT_CONN", "60055");
		parameters.put("USERNAME", "test_user");
		parameters.put("PW", "2m;z#MkD-tcc-guilherme");
		parameters.put("MAX_CONNECTIONS", "1");

		KNetRequester kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, parameters),
				parameters.get("USERNAME"), parameters.get("PW"));

		return new KeyManager(kNetRequester);
	}
}
