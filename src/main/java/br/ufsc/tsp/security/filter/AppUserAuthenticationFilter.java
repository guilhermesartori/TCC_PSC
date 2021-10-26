package br.ufsc.tsp.security.filter;

import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.response.AuthenticationResponse;
import br.ufsc.tsp.utility.JWTManager;

public class AppUserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

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
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
				password);
		return authenticationManager.authenticate(authenticationToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		var jwtManager = new JWTManager();
		var user = (User) authResult.getPrincipal();
		var username = user.getUsername();
		var issuer = request.getRequestURL().toString();
		var roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
		var accessToken = jwtManager.createAccessToken(username, issuer, roles);
		var refreshToken = jwtManager.createRefreshToken(username, issuer);
		var authenticationResponseBody = new AuthenticationResponse(accessToken, refreshToken);
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
