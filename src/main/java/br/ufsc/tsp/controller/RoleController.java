package br.ufsc.tsp.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.service.RoleService;

@RestController
@RequestMapping(path = "role")
public class RoleController {

	private final RoleService roleService;

	/**
	 * @param appUserService
	 */
	@Autowired
	public RoleController(RoleService roleService) {
		super();
		this.roleService = roleService;
	}

	@PostMapping(path = "role")
	public ResponseEntity<Object> saveRole(@RequestBody Role role) {
		var uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/role").toUriString());
		return ResponseEntity.created(uri).body(roleService.saveRole(role));
	}

}
