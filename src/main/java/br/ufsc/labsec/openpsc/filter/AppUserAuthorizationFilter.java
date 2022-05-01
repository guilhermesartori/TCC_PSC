package br.ufsc.labsec.openpsc.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.service.JWTManager;

public class AppUserAuthorizationFilter extends OncePerRequestFilter {

	private static final String AUTH_HEADER_START = "Bearer ";

	private final JWTManager jwtManager;

	public AppUserAuthorizationFilter(JWTManager jwtManager) {
		this.jwtManager = jwtManager;
	}

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
