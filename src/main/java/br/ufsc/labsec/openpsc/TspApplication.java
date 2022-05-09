package br.ufsc.labsec.openpsc;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.security.SecuritySchemes;

@SpringBootApplication
@SecuritySchemes(value = {
		@SecurityScheme(type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT", name = "administrator", description = "Schema referring to a JWT obtained by an administrator user."),
		@SecurityScheme(type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT", name = "user", description = "Schema referring to a JWT obtained by a non-administrator user.") })
public class TspApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(TspApplication.class, args);
	}

}
