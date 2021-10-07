package br.ufsc.tsp.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.response.ErrorMessageResponse;

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
					var algorithm = Algorithm.HMAC256("secret".getBytes());
					var jwtVerifier = JWT.require(algorithm).build();
					var decodedJWT = jwtVerifier.verify(token);
					var username = decodedJWT.getSubject();
					var roles = decodedJWT.getClaim("roles").asArray(String.class);
					var authorities = new ArrayList<SimpleGrantedAuthority>();
					Arrays.stream(roles).forEach(role -> {
						authorities.add(new SimpleGrantedAuthority(role));
					});
					var authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
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
