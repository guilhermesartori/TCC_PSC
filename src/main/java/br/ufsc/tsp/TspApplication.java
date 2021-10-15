package br.ufsc.tsp;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.RoleService;

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
	CommandLineRunner run(AppUserService userService, RoleService roleService) {
		return args -> {
			roleService.saveRole(new Role(null, "ROLE_USER"));
			roleService.saveRole(new Role(null, "ROLE_MANAGER"));
			roleService.saveRole(new Role(null, "ROLE_ADMIN"));
			roleService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new AppUser(null, "Guilherme Sartori", "guilherme", "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Fulano de Tal", "fulano", "fulano", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Usuario Teste", "usuario", "passwordsenha", new ArrayList<>()));

			userService.addRoleToUser("guilherme", "ROLE_ADMIN");
			userService.addRoleToUser("guilherme", "ROLE_USER");
			userService.addRoleToUser("guilherme", "ROLE_MANAGER");
			userService.addRoleToUser("guilherme", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("fulano", "ROLE_MANAGER");
			userService.addRoleToUser("usuario", "ROLE_USER");

		};
	}

}
