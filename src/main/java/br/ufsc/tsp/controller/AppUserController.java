package br.ufsc.tsp.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.controller.request.RegisterUserRequest;
import br.ufsc.tsp.controller.request.RoleToUserForm;
import br.ufsc.tsp.controller.response.UserResponse;
import br.ufsc.tsp.service.AppUserService;

@RestController
@RequestMapping(path = "user")
public class AppUserController {

	private final AppUserService appUserService;

	/**
	 * @param appUserService
	 */
	@Autowired
	public AppUserController(AppUserService appUserService) {
		super();
		this.appUserService = appUserService;
	}

	@GetMapping
	public ResponseEntity<Object> getUsers() {
		return ResponseEntity.ok().body(appUserService.getUsers());
	}

	@PostMapping
	public ResponseEntity<Object> registerUser(@RequestBody RegisterUserRequest registerUserRequest) {
		var name = registerUserRequest.getName();
		var username = registerUserRequest.getUsername();
		var password = registerUserRequest.getPassword();
		var createdUser = appUserService.registerNewUser(name, username, password);
		var createdUserId = createdUser.getId();
		var pathToCreatedUser = String.format("/user/%d", createdUserId);
		var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedUser).toUriString();
		var uri = URI.create(uriString);
		return ResponseEntity.created(uri).body(createdUser);
	}

	@GetMapping(path = "{username}")
	public ResponseEntity<Object> getUser(@PathVariable("username") String username) {
		var user = appUserService.getUser(username);
		var userResponseBody = new UserResponse();
		userResponseBody.setUsername(user.getUsername());
		userResponseBody.setAuthority(user.getAuthorities().iterator().next().toString());
		return ResponseEntity.ok().body(userResponseBody);
	}

	@PostMapping(path = "{username}/authority")
	public ResponseEntity<Object> addRoleToUser(@PathVariable("username") String username,
			@RequestBody RoleToUserForm role) {
		appUserService.addRoleToUser(username, role.getRoleName());
		return ResponseEntity.ok().build();
	}

}
