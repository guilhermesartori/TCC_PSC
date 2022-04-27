package br.ufsc.tsp.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.data.response.ErrorMessageResponse;
import br.ufsc.tsp.service.JWTManager;

public class AppUserAuthorizationFilter extends OncePerRequestFilter {

	@Autowired
	private JWTManager jwtManager;

	private static final String AUTH_HEADER_START = "Bearer ";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith(AUTH_HEADER_START)) {
			try {
				final var token = authorizationHeader.substring(AUTH_HEADER_START.length());
				final var decodedJWTManager = jwtManager.decode(token);
				final var principal = decodedJWTManager.getUsername();
				final var authorities = decodedJWTManager.getAuthorities();
				final var encodedAccessKey = decodedJWTManager.getAccessKey();
				final var authenticationToken = new UsernamePasswordAuthenticationToken(principal, encodedAccessKey,
						authorities);
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			} catch (Exception e) {
				e.printStackTrace();
				final var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.setStatus(HttpStatus.FORBIDDEN.value());
				new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
			}
		}
		filterChain.doFilter(request, response);
	}

}
