package br.ufsc.labsec.openpsc.controller;

import java.net.URI;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.labsec.openpsc.data.request.KNetConfigurationRequest;
import br.ufsc.labsec.openpsc.data.request.RegisterUserRequest;
import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.data.response.UserResponse;
import br.ufsc.labsec.openpsc.service.SystemConfigurationService;
import br.ufsc.labsec.openpsc.service.exception.SystemServiceException;

@RestController
@RequestMapping(path = "system")
public class SystemConfigurationController {

	@Autowired
	private SystemConfigurationService systemConfigurationService;

	@PostMapping("admin-user")
	public ResponseEntity<Object> createSystemAdmin(@RequestBody RegisterUserRequest registerUserRequest) {
		try {
			final var username = registerUserRequest.getUsername();
			final var password = registerUserRequest.getPassword();
			final var createdUser = systemConfigurationService.createAdministratorUser(username, password);
			final var userResponseBody = new UserResponse();
			userResponseBody.setUsername(createdUser.getUsername());
			userResponseBody.setAuthority(createdUser.getAuthority().name());
			final var createdUserId = createdUser.getId();
			final var pathToCreatedUser = String.format("/user/%d", createdUserId);
			final var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedUser).toUriString();
			final var uri = URI.create(uriString);
			return ResponseEntity.created(uri).body(userResponseBody);
		} catch (SystemServiceException e) {
			return ResponseEntity.badRequest().body(new ErrorMessageResponse(e.getMessage()));
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@PutMapping("hsm-config")
	public ResponseEntity<Object> setKnetConfiguration(@RequestBody KNetConfigurationRequest request) {
		try {
			final var encryptedAccessKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			systemConfigurationService.setKnetConfiguration(request.getParameters(), encryptedAccessKey);
			return ResponseEntity.ok().build();
		} catch (SystemServiceException e) {
			final var errorResponse = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(errorResponse);
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@PostMapping("hsm-config/load")
	public ResponseEntity<Object> loadKnetConfiguration() {
		try {
			final var encryptedAccessKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			systemConfigurationService.loadKnetConfiguration(encryptedAccessKey);
			return ResponseEntity.ok().build();
		} catch (SystemServiceException e ) {
			final var errorResponse = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(errorResponse);
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().build();
		}
	}

	@PostMapping("refresh-key")
	public ResponseEntity<Object> refreshSystemKey() {
		try {
			systemConfigurationService.refreshSystemKey();
			return ResponseEntity.ok().build();
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().build();
		}
	}

}
