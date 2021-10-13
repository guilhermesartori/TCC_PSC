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
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.RoleRepository;

@Service
@Transactional
public class AppUserService implements UserDetailsService {

	private final AppUserRepository appUserRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;

	@Autowired
	public AppUserService(AppUserRepository appUserRepository, RoleRepository roleRepository,
			PasswordEncoder passwordEncoder) {
		super();
		this.appUserRepository = appUserRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = appUserRepository.findByUsername(username);
		if (appUser == null)
			throw new UsernameNotFoundException(String.format("User %s not found", username));
		var authorities = new ArrayList<SimpleGrantedAuthority>();
		appUser.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
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

	public void addRoleToUser(String username, String roleName) {
		var appUser = appUserRepository.findByUsername(username);
		var role = roleRepository.findByName(roleName);
		appUser.getRoles().add(role);
	}

}
