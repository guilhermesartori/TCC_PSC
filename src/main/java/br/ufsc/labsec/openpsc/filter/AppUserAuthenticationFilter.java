package br.ufsc.labsec.openpsc.filter;

import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.ufsc.labsec.openpsc.data.response.AuthenticationResponse;
import br.ufsc.labsec.openpsc.service.JWTManager;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AppUserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	@Autowired
	private JWTManager jwtManager;
	
	private final AuthenticationManager authenticationManager;

	/**
	 * @param authenticationManager
	 */
	public AppUserAuthenticationFilter(AuthenticationManager authenticationManager) {
		super();
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		final var username = request.getParameter("username");
		final var password = request.getParameter("password");
		final var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
		return authenticationManager.authenticate(authenticationToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		final var user = (User) authResult.getPrincipal();
		final var username = user.getUsername();
		final var password = user.getPassword();
		final var issuer = request.getRequestURL().toString();
		final var roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
		final var accessToken = jwtManager.createAccessToken(username, password, issuer, roles);
		final var authenticationResponseBody = new AuthenticationResponse(accessToken);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponseBody);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		super.unsuccessfulAuthentication(request, response, failed);
		failed.printStackTrace();
	}

}
