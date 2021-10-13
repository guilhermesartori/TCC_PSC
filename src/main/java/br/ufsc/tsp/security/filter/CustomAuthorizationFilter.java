package br.ufsc.tsp.security.filter;

import java.io.IOException;

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

public class CustomAuthorizationFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (request.getServletPath().equals("/login") || request.getServletPath().equals("/refresh-token"))
			filterChain.doFilter(request, response);
		else {
			var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				try {
					var token = authorizationHeader.substring("Bearer ".length());
					var decodedJWTManager = new JWTManager().decode(token);
					var principal = decodedJWTManager.getUsername();
					var authorities = decodedJWTManager.getAuthorities();
					var authenticationToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					filterChain.doFilter(request, response);
				} catch (Exception e) {
					e.printStackTrace();
					var errorMessageResponse = new ErrorMessageResponse(e.getMessage());
					response.setContentType(MediaType.APPLICATION_JSON_VALUE);
					response.setStatus(HttpStatus.FORBIDDEN.value());
					new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
				}
			} else {
				filterChain.doFilter(request, response);
			}
		}
	}

}
