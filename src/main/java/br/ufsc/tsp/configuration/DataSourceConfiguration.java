package br.ufsc.tsp.configuration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;

import javax.sql.DataSource;

import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

@Configuration
public class DataSourceConfiguration {

	private static final String SEPARATOR = System.getProperty("file.separator");
	private static final String PATH_TO_FILE = SEPARATOR + "etc" + SEPARATOR + "psc" + SEPARATOR + "settings.json";

	@Bean
	public DataSource customDataSource() throws IOException {
		checkFilePermissions();
		final var gson = new Gson();
		final var reader = Files.newBufferedReader(Paths.get(PATH_TO_FILE));
		final var json = gson.fromJson(reader, JsonObject.class);
		final var databaseConfig = json.get("databaseConfiguration").getAsJsonObject();
		final var url = databaseConfig.get("url").getAsString();
		final var username = databaseConfig.get("username").getAsString();
		final var password = databaseConfig.get("password").getAsString();
		final var dsBuilder = DataSourceBuilder.create();
		dsBuilder.driverClassName("com.mysql.cj.jdbc.Driver");
		dsBuilder.url(url);
		dsBuilder.username(username);
		dsBuilder.password(password);
		return dsBuilder.build();
	}

	private File checkFilePermissions() throws IOException {
		File file = new File(PATH_TO_FILE);
		var permissions = Files.getPosixFilePermissions(Paths.get(PATH_TO_FILE));
		if (permissions.contains(PosixFilePermission.OTHERS_READ)
				|| permissions.contains(PosixFilePermission.OTHERS_WRITE))
			throw new RuntimeException(String.format("Bad file permissions. File %s is others readable or writable.", PATH_TO_FILE));
		if (permissions.contains(PosixFilePermission.GROUP_READ)
				|| permissions.contains(PosixFilePermission.GROUP_EXECUTE))
			throw new RuntimeException(String.format("Bad file permissions. File %s is group readable or writable.", PATH_TO_FILE));
		return file;
	}

}
