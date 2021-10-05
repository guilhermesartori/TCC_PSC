package br.ufsc.tsp.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.controller.request.RoleToUserForm;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.Role;
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
	public ResponseEntity<Object> saveUser(@RequestBody AppUser user) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user").toUriString());
		return ResponseEntity.created(uri).body(appUserService.saveUser(user));
	}

	@PostMapping(path = "role")
	public ResponseEntity<Object> saveRole(@RequestBody Role role) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/role").toUriString());
		return ResponseEntity.created(uri).body(appUserService.saveRole(role));
	}

	@PostMapping(path = "add-role")
	public ResponseEntity<Object> addRoleToUser(@RequestBody RoleToUserForm role) {
		appUserService.addRoleToUser(role.getUsername(), role.getRoleName());
		return ResponseEntity.ok().build();
	}

}
