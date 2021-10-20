package br.ufsc.tsp.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.utility.JWTManager;

public class CustomAuthorizationFilter implements Filter {

	private static final String AUTH_HEADER_START = "Bearer ";
	private static final String RESPONSE_ERROR_MESSAGE = "User does not contain %s authority.";

	private String httpMethod;
	private String authority;

	/**
	 * @param httpMethod
	 * @param authority
	 */
	public CustomAuthorizationFilter(String httpMethod, String authority) {
		super();
		this.httpMethod = httpMethod;
		this.authority = authority;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;

		if (httpRequest.getMethod() != httpMethod) {
			chain.doFilter(request, response);
			return;
		}

		var authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith(AUTH_HEADER_START)) {
			var token = authorizationHeader.substring(AUTH_HEADER_START.length());
			var decodedJWTManager = new JWTManager().decode(token);
			var authorities = decodedJWTManager.getAuthorities();

			if (authorities.contains(new SimpleGrantedAuthority(authority)))
				chain.doFilter(request, response);
			else {
				var message = String.format(RESPONSE_ERROR_MESSAGE, authority);
				var errorMessageResponse = new ErrorMessageResponse(message);
				httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
				httpResponse.setStatus(HttpStatus.FORBIDDEN.value());
				new ObjectMapper().writeValue(response.getOutputStream(), errorMessageResponse);
			}
		} else
			chain.doFilter(request, response);
	}

	@Bean
	public FilterRegistrationBean<CustomAuthorizationFilter> createKeyFilter() {
		FilterRegistrationBean<CustomAuthorizationFilter> registrationBean = new FilterRegistrationBean<>();

		registrationBean.setFilter(
				new CustomAuthorizationFilter(HttpMethod.POST.toString(), Authority.CREATE_KEY.toString()));
		registrationBean.addUrlPatterns("/key/**");

		return registrationBean;
	}

}
