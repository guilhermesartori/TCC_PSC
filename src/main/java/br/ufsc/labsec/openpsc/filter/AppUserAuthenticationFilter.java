package br.ufsc.labsec.openpsc.filter;

import java.io.IOException;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import br.ufsc.labsec.openpsc.data.request.AuthenticationRequest;
import br.ufsc.labsec.openpsc.data.response.AuthenticationResponse;
import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.service.JWTManager;

public class AppUserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private static final String BAD_CREDENTIALS = "Invalid username or password.";

  private final JWTManager jwtManager;
  private final AuthenticationManager authenticationManager;

  /**
   * @param authenticationManager
   */
  public AppUserAuthenticationFilter(AuthenticationManager authenticationManager,
      JWTManager jwtManager) {
    super();
    this.authenticationManager = authenticationManager;
    this.jwtManager = jwtManager;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    try {
      final var authenticationRequest =
          new ObjectMapper().readValue(request.getInputStream(), AuthenticationRequest.class);
      final var username = authenticationRequest.getUsername();
      final var password = authenticationRequest.getPassword();
      final var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
      return authenticationManager.authenticate(authenticationToken);
    } catch (IOException e) {
      return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("", ""));
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    final var user = (User) authResult.getPrincipal();
    final var username = user.getUsername();
    final var password = user.getPassword();
    final var issuer = request.getRequestURL().toString();
    final var roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList());
    final var accessToken = jwtManager.createAccessToken(username, password, issuer, roles);
    final var authenticationResponseBody = new AuthenticationResponse(accessToken);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponseBody);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException failed)
      throws IOException, ServletException {
    final var error = new ErrorMessageResponse();
    error.setError(BAD_CREDENTIALS);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    new ObjectMapper().writeValue(response.getOutputStream(), BAD_CREDENTIALS);
  }

}
