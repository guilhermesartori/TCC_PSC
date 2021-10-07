package br.ufsc.tsp.controller;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
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

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.request.RoleToUserForm;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
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

	@GetMapping(path = "/refresh-token")
	public void getNewTokenFromRefreshToken(HttpServletRequest request, HttpServletResponse response)
			throws JsonGenerationException, JsonMappingException, IOException {
		var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				var refreshToken = authorizationHeader.substring("Bearer ".length());
				var algorithm = Algorithm.HMAC256("secret".getBytes());
				var jwtVerifier = JWT.require(algorithm).build();
				var decodedJWT = jwtVerifier.verify(refreshToken);
				var username = decodedJWT.getSubject();
				var user = appUserService.getUser(username);
				var accessToken = JWT.create().withSubject(user.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
						.withIssuer(request.getRequestURL().toString())
						.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
						.sign(algorithm);
				var tokens = new HashMap<String, String>();
				tokens.put("access_token", accessToken);
				tokens.put("refresh_token", refreshToken);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
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
