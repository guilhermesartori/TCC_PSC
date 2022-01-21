package br.ufsc.tsp.configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.sql.DataSource;

import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

// TODO runtime configuration?
@Configuration
public class DataSourceConfiguration {

//	spring.datasource.url=jdbc:mysql://localhost:3306/tsp
//	spring.datasource.username=labsec
//	spring.datasource.password=labsec
//	spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

	private static final String SEPARATOR = System.getProperty("file.separator");
	private static final String PATH_TO_FILE = SEPARATOR + "etc" + SEPARATOR + "psc" + SEPARATOR + "settings.json";

	@Lazy
	@Bean
	public DataSource customDataSource() throws IOException {
		var gson = new Gson();
		var reader = Files.newBufferedReader(Paths.get(PATH_TO_FILE));
		var json = gson.fromJson(reader, JsonObject.class);
		var databaseConfig = json.get("databaseConfiguration").getAsJsonObject();
		var url = databaseConfig.get("url").getAsString();
		var username = databaseConfig.get("username").getAsString();
		var password = databaseConfig.get("password").getAsString();
		var dsBuilder = DataSourceBuilder.create();
		dsBuilder.driverClassName("com.mysql.cj.jdbc.Driver");
		dsBuilder.url(url);
		dsBuilder.username(username);
		dsBuilder.password(password);
		return dsBuilder.build();
	}

}
