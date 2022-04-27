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

import br.ufsc.tsp.data.request.RegisterUserRequest;
import br.ufsc.tsp.data.response.ErrorMessageResponse;
import br.ufsc.tsp.data.response.UserResponse;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.exception.AppUserServiceException;

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
		final var username = registerUserRequest.getUsername();
		final var password = registerUserRequest.getPassword();
		try {
			final var createdUser = appUserService.registerNewUser(username, password);
			final var userResponseBody = new UserResponse();
			userResponseBody.setUsername(createdUser.getUsername());
			userResponseBody.setAuthority(createdUser.getAuthority().name());
			final var createdUserId = createdUser.getId();
			final var pathToCreatedUser = String.format("/user/%d", createdUserId);
			final var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedUser).toUriString();
			final var uri = URI.create(uriString);
			return ResponseEntity.created(uri).body(userResponseBody);
		} catch (AppUserServiceException e) {
			return ResponseEntity.badRequest().body(new ErrorMessageResponse(e.getMessage()));
		} catch (Throwable e) {
			return ResponseEntity.internalServerError().body(new ErrorMessageResponse());
		}
	}

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
