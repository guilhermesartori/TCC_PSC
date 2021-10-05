package br.ufsc.tsp.security;

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

import br.ufsc.tsp.security.filter.CustomAuthenticationFilter;
import br.ufsc.tsp.security.filter.CustomAuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;

	/**
	 * @param userDetailsService
	 * @param passwordEncoder
	 */
	@Autowired
	public SecurityConfiguration(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		super();
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
		authenticationFilter.setFilterProcessesUrl("/login");
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests().antMatchers(HttpMethod.POST, "/login").permitAll();
		http.authorizeRequests().antMatchers(HttpMethod.GET, "/user/**").hasAnyAuthority("ROLE_ADMIN");
		http.authorizeRequests().antMatchers(HttpMethod.POST, "/user/add-role").hasAnyAuthority("ROLE_ADMIN");
		http.authorizeRequests().antMatchers(HttpMethod.POST, "/key-pair").hasAnyAuthority("ROLE_USER");
		http.authorizeRequests().anyRequest().authenticated();
		http.addFilter(authenticationFilter);
		http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
