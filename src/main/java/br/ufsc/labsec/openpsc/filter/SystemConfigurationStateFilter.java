package br.ufsc.labsec.openpsc.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.service.SystemConfigurationService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.ClientResponse.Status;

@Component
@Order(1)
public class SystemConfigurationStateFilter extends OncePerRequestFilter {

  private static final String ERROR_MESSAGE = "System not configured.";

  private static final String USER_PATH = "/user";
  private static final String KEY_PATH = "/key";

  @Autowired
  private SystemConfigurationService systemConfigurationService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    final var requestURI = request.getRequestURI();
    if ((!requestURI.startsWith(USER_PATH) && !requestURI.startsWith(KEY_PATH))
        || systemConfigurationService.isSystemConfigured())
      filterChain.doFilter(request, response);
    else {
      response.setStatus(Status.BAD_REQUEST.getStatusCode());
      final var responseBody = new ErrorMessageResponse();
      responseBody.setError(ERROR_MESSAGE);
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      new ObjectMapper().writeValue(response.getOutputStream(), responseBody);
    }
  }

}
