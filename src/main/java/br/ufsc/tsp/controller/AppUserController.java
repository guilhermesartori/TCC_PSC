package br.ufsc.tsp.controller;

import java.io.IOException;
import java.net.URI;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.request.RoleToUserForm;
import br.ufsc.tsp.controller.response.AuthenticationResponse;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.utility.JWTManager;

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
		var uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user").toUriString());
		return ResponseEntity.created(uri).body(appUserService.saveUser(user));
	}

	@PostMapping(path = "role")
	public ResponseEntity<Object> saveRole(@RequestBody Role role) {
		var uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/role").toUriString());
		return ResponseEntity.created(uri).body(appUserService.saveRole(role));
	}

	@PostMapping(path = "add-role")
	public ResponseEntity<Object> addRoleToUser(@RequestBody RoleToUserForm role) {
		appUserService.addRoleToUser(role.getUsername(), role.getRoleName());
		return ResponseEntity.ok().build();
	}

	@GetMapping(path = "/refresh-token")
	public void getNewTokenFromRefreshToken(HttpServletRequest request, HttpServletResponse response)
			throws JsonGenerationException, JsonMappingException, IOException {
		var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				var refreshToken = authorizationHeader.substring("Bearer ".length());
				var jwtManager = new JWTManager();
				var decodedJwtManager = jwtManager.decode(refreshToken);
				var username = decodedJwtManager.getUsername();
				var user = appUserService.getUser(username);
				var issuer = request.getRequestURL().toString();
				var roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
				var accessToken = jwtManager.createAccessToken(username, issuer, roles);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				var authenticationResponseBody = new AuthenticationResponse(accessToken, refreshToken);
				new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponseBody);
			} catch (Exception e) {
				e.printStackTrace();
				var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setStatus(HttpStatus.FORBIDDEN.value());
				new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
			}
		} else {
			throw new RuntimeException("Refresh token is missing");
		}

	}

}
