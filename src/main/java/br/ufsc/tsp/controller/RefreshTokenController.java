package br.ufsc.tsp.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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
	public void getNewTokenFromRefreshToken(HttpServletRequest request, HttpServletResponse response)
			throws JsonGenerationException, JsonMappingException, IOException {
		var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (!(authorizationHeader != null && authorizationHeader.startsWith("Bearer "))) {
			throw new RuntimeException("Refresh token is missing");
		}
		var refreshToken = authorizationHeader.substring("Bearer ".length());
		var issuer = request.getRequestURL().toString();
		try {
			var accessToken = authenticationService.generateNewAccessToken(refreshToken, issuer);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			var authenticationResponseBody = new AuthenticationResponse(accessToken, refreshToken);
			new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponseBody);
		} catch (Exception e) {
			var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setStatus(HttpStatus.FORBIDDEN.value());
			new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
		}
	}

}
