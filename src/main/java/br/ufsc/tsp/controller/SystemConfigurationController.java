package br.ufsc.tsp.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.controller.request.KNetConfigurationRequest;
import br.ufsc.tsp.controller.request.RegisterUserRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.service.SystemService;
import br.ufsc.tsp.service.exception.SystemServiceException;

// TODO custom DB?
// TODO custom DB admin?
@RestController
@RequestMapping(path = "system")
public class SystemConfigurationController {

	@Autowired
	private SystemService systemService;

	@PostMapping("admin-user")
	public ResponseEntity<Object> createSystemAdmin(@RequestBody RegisterUserRequest registerUserRequest) {
		try {
			var name = registerUserRequest.getName();
			var username = registerUserRequest.getUsername();
			var password = registerUserRequest.getPassword();
			var createdUser = systemService.createAdministratorUser(name, username, password);
			var createdUserId = createdUser.getId();
			var pathToCreatedUser = String.format("/user/%d", createdUserId);
			var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedUser).toUriString();
			var uri = URI.create(uriString);
			return ResponseEntity.created(uri).body(createdUser);
		} catch (SystemServiceException e) {
			return ResponseEntity.badRequest().body(new ErrorMessageResponse(e.getMessage()));
		}
	}

	@PostMapping("knet")
	public ResponseEntity<Object> createKnetConfiguration(KNetConfigurationRequest request) {
		try {
			systemService.createKnetConfiguration(request.getParameters());
			return ResponseEntity.ok().build();
		} catch (SystemServiceException e) {
			var errorResponse = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(errorResponse);
		}
	}

	@PostMapping("refresh-key")
	public ResponseEntity<Object> refreshSystemKey() {
		systemService.refreshSystemKey();
		return ResponseEntity.ok().build();
	}

}
