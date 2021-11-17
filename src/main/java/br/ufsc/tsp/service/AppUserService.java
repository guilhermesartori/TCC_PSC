package br.ufsc.tsp.service;

import java.util.ArrayList;
import java.util.Collection;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;

@Service
@Transactional
public class AppUserService implements UserDetailsService {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;

	@Autowired
	public AppUserService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
		super();
		this.appUserRepository = appUserRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = appUserRepository.findByUsername(username);
		if (appUser == null)
			throw new UsernameNotFoundException(String.format("User %s not found", username));
		var authorities = new ArrayList<SimpleGrantedAuthority>();
		appUser.getAuthorities().forEach(authority -> {
			authorities.add(new SimpleGrantedAuthority(authority.toString()));
		});
		return new User(appUser.getUsername(), appUser.getPassword(), authorities);
	}

	public AppUser saveUser(AppUser user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return appUserRepository.save(user);
	}

	public AppUser getUser(String username) {
		return appUserRepository.findByUsername(username);
	}

	public Collection<AppUser> getUsers() {
		return appUserRepository.findAll();
	}

	public void addRoleToUser(String username, Authority authority) {
		var appUser = appUserRepository.findByUsername(username);
		appUser.getAuthorities().add(authority);
	}

	public void addRoleToUser(String username, String authorityName) {
		var authority = Authority.valueOf(authorityName);
		addRoleToUser(username, authority);
	}

	public void deleteUserByUsername(String username) {
		appUserRepository.deleteByUsername(username);
	}

}
