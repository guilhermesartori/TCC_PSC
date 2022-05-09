package br.ufsc.labsec.openpsc.controller;

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

import br.ufsc.labsec.openpsc.data.request.RegisterUserRequest;
import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.data.response.UserResponse;
import br.ufsc.labsec.openpsc.service.AppUserService;
import br.ufsc.labsec.openpsc.service.exception.AppUserServiceException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

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

	@SecurityRequirement(name = "administrator")
	@GetMapping
	public ResponseEntity<Object> getUsers() {
		return ResponseEntity.ok().body(appUserService.getUsers());
	}

	@Operation(responses = @ApiResponse(responseCode = "400"))
	@PostMapping
	public ResponseEntity<Object> registerUser(@RequestBody RegisterUserRequest registerUserRequest) {
		final var username = registerUserRequest.getUsername();
		final var password = registerUserRequest.getPassword();
		try {
			final var createdUser = appUserService.registerNewUser(username, password);
			final var userResponseBody = new UserResponse();
			userResponseBody.setUsername(createdUser.getUsername());
			userResponseBody.setAuthority(createdUser.getAuthority().name());
			final var createdUserId = createdUser.getId();
			final var pathToCreatedUser = String.format("/user/%d", createdUserId);
			final var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedUser)
					.toUriString();
			final var uri = URI.create(uriString);
			return ResponseEntity.created(uri).body(userResponseBody);
		} catch (AppUserServiceException e) {
			return ResponseEntity.badRequest().body(new ErrorMessageResponse(e.getMessage()));
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().body(new ErrorMessageResponse());
		}
	}

	@SecurityRequirement(name = "administrator")
	@GetMapping(path = "{username}")
	public ResponseEntity<Object> getUser(@PathVariable("username") String username) {
		try {
			final var user = appUserService.getUser(username);
			final var userResponseBody = new UserResponse();
			userResponseBody.setUsername(user.getUsername());
			userResponseBody.setAuthority(user.getAuthority().name());
			return ResponseEntity.ok().body(userResponseBody);
		} catch (AppUserServiceException e) {
			return ResponseEntity.badRequest().body(new ErrorMessageResponse(e.getMessage()));
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().body(new ErrorMessageResponse());
		}
	}

}
