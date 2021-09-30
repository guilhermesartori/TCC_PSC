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
import org.springframework.stereotype.Service;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.RoleRepository;

@Service
@Transactional
public class AppUserService implements UserDetailsService {

	private final AppUserRepository appUserRepository;
	private final RoleRepository roleRepository;

	@Autowired
	public AppUserService(AppUserRepository appUserRepository, RoleRepository roleRepository) {
		super();
		this.appUserRepository = appUserRepository;
		this.roleRepository = roleRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = appUserRepository.findByUsername(username);
		if (appUser == null)
			throw new UsernameNotFoundException(String.format("User %s not found", username));
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		appUser.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new User(appUser.getUsername(), appUser.getName(), authorities);
	}

	public AppUser saveUser(AppUser user) {
		return appUserRepository.save(user);
	}

	public AppUser getUser(String username) {
		return appUserRepository.findByUsername(username);
	}

	public Collection<AppUser> getUsers() {
		return appUserRepository.findAll();
	}

	public Role saveRole(Role role) {
		return roleRepository.save(role);
	}

	public void addRoleToUser(String username, String roleName) {
		AppUser appUser = appUserRepository.findByUsername(username);
		Role role = roleRepository.findByName(roleName);
		appUser.getRoles().add(role);
	}

}
