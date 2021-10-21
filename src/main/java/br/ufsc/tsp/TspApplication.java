package br.ufsc.tsp;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.service.AppUserService;

@SpringBootApplication
public class TspApplication {

	public static void main(String[] args) {
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

}
