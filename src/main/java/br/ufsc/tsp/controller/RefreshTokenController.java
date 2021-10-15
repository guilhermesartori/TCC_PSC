package br.ufsc.tsp.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;

import br.ufsc.tsp.controller.response.AuthenticationResponse;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.service.AuthenticationService;

@RestController
@RequestMapping(path = "refresh-token")
public class RefreshTokenController {

	private final AuthenticationService authenticationService;

	/**
	 * @param authenticationService
	 */
	@Autowired
	public RefreshTokenController(AuthenticationService authenticationService) {
		super();
		this.authenticationService = authenticationService;
	}

	@GetMapping
	public ResponseEntity<Object> getNewTokenFromRefreshToken(HttpServletRequest request)
			throws JsonGenerationException, JsonMappingException, IOException {
		var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (!(authorizationHeader != null && authorizationHeader.startsWith("Bearer "))) {
			var errorMessageResponse = new ErrorMessageResponse("Refresh token is missing.");
			return ResponseEntity.status(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON)
					.body(errorMessageResponse);
		}
		var refreshToken = authorizationHeader.substring("Bearer ".length());
		var issuer = request.getRequestURL().toString();
		try {
			var accessToken = authenticationService.generateNewAccessToken(refreshToken, issuer);
			var authenticationResponseBody = new AuthenticationResponse(accessToken, refreshToken);
			return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(authenticationResponseBody);
		} catch (Exception e) {
			var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.status(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON)
					.body(errorMessageResponse);
		}
	}

}
