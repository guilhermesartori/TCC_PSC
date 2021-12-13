package br.ufsc.tsp.controller.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class RegisterUserRequest {

	private String name;

	private String username;

	private String password;

}
