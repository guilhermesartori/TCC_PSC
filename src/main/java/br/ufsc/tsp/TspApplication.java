package br.ufsc.tsp;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// TODO System should not start without being configured
@SpringBootApplication
public class TspApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(TspApplication.class, args);
	}

}
