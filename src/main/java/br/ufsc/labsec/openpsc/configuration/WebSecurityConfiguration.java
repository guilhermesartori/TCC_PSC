package br.ufsc.labsec.openpsc.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.ufsc.labsec.openpsc.entity.enums.Authority;
import br.ufsc.labsec.openpsc.filter.AppUserAuthenticationFilter;
import br.ufsc.labsec.openpsc.filter.AppUserAuthorizationFilter;
import br.ufsc.labsec.openpsc.service.JWTManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;
  private final JWTManager jwtManager;

  /**
   * @param userDetailsService
   * @param passwordEncoder
   */
  @Autowired
  public WebSecurityConfiguration(UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder, JWTManager jwtManager) {
    super();
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;
    this.jwtManager = jwtManager;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    final var authenticationFilter =
        new AppUserAuthenticationFilter(authenticationManagerBean(), jwtManager);

    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    // /user
    http.authorizeRequests().antMatchers(HttpMethod.GET, "/user")
        .hasAnyAuthority(Authority.ADMINISTRATOR.toString());
    http.authorizeRequests().antMatchers(HttpMethod.GET, "/user/**")
        .hasAnyAuthority(Authority.ADMINISTRATOR.toString());

    // /key
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/key")
        .hasAnyAuthority(Authority.USER.toString());
    http.authorizeRequests().antMatchers(HttpMethod.GET, "/key")
        .hasAnyAuthority(Authority.USER.toString());
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/key/**/sign")
        .hasAnyAuthority(Authority.USER.toString());
    http.authorizeRequests().antMatchers(HttpMethod.DELETE, "/key/**")
        .hasAnyAuthority(Authority.USER.toString());
    http.authorizeRequests().antMatchers(HttpMethod.GET, "/key/**")
        .hasAnyAuthority(Authority.USER.toString());

    // /system
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/system/hsm-config/**")
        .hasAnyAuthority(Authority.ADMINISTRATOR.toString());
    http.authorizeRequests().antMatchers(HttpMethod.PUT, "/system/hsm-config/**")
        .hasAnyAuthority(Authority.ADMINISTRATOR.toString());
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/system/refresh-key")
        .hasAnyAuthority(Authority.ADMINISTRATOR.toString());
    http.authorizeRequests().antMatchers(HttpMethod.POST, "/system/admin-user").permitAll();

    // filters
    http.addFilter(authenticationFilter);
    http.addFilterBefore(new AppUserAuthorizationFilter(jwtManager),
        UsernamePasswordAuthenticationFilter.class);
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

}
