package br.ufsc.tsp.configuration;

import javax.sql.DataSource;

import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Configuration
public class DataSourceConfiguration {

//	spring.datasource.url=jdbc:mysql://localhost:3306/tsp
//	spring.datasource.username=labsec
//	spring.datasource.password=labsec
//	spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

	private static String url = "jdbc:mysql://localhost:3306/tsp";
	private static String username = "labsec";
	private static String password = "labsec";

	@Lazy
	@Bean
	public DataSource customDataSource() {
		var dsBuilder = DataSourceBuilder.create();
		dsBuilder.driverClassName("com.mysql.cj.jdbc.Driver");
		dsBuilder.url(url);
		dsBuilder.username(username);
		dsBuilder.password(password);
		return dsBuilder.build();
	}

}
