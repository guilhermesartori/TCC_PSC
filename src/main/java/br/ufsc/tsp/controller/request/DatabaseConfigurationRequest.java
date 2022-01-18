package br.ufsc.tsp.controller.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DatabaseConfigurationRequest {

	private String url;
	private String username;
	private String password;

}