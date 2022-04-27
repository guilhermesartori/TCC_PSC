package br.ufsc.labsec.openpsc;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TspApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(TspApplication.class, args);
	}

}
