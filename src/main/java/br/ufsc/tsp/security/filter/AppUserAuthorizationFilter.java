package br.ufsc.tsp.security.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.utility.JWTManager;

public class AppUserAuthorizationFilter extends OncePerRequestFilter {

	private static final Collection<String> unfilteredPaths;
	private static final String AUTH_HEADER_START = "Bearer ";

	static {
		unfilteredPaths = new HashSet<>();
		unfilteredPaths.add("/login");
		unfilteredPaths.add("/refresh-token");
		unfilteredPaths.add("/user");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!unfilteredPaths.contains(request.getServletPath())) {
			var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (authorizationHeader != null && authorizationHeader.startsWith(AUTH_HEADER_START)) {
				try {
					var token = authorizationHeader.substring(AUTH_HEADER_START.length());
					var decodedJWTManager = new JWTManager().decode(token);
					var principal = decodedJWTManager.getUsername();
					var authorities = decodedJWTManager.getAuthorities();
					var encodedAccessKey = decodedJWTManager.getAccessKey();
					var authenticationToken = new UsernamePasswordAuthenticationToken(principal, encodedAccessKey, authorities);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					filterChain.doFilter(request, response);
					return;
				} catch (Exception e) {
					e.printStackTrace();
					var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
					response.setContentType(MediaType.APPLICATION_JSON_VALUE);
					response.setStatus(HttpStatus.FORBIDDEN.value());
					new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
				}
			}
		}
		filterChain.doFilter(request, response);
	}

}
