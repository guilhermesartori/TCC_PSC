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

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.service.exception.AppUserServiceException;
import br.ufsc.tsp.service.exception.AppUserServiceException.ExceptionType;

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
		var optionalUser = appUserRepository.findAppUserByUsername(username);
		if (optionalUser.isEmpty())
			throw new UsernameNotFoundException(String.format("User %s not found", username));
		var appUser = optionalUser.get();
		var authorities = new ArrayList<SimpleGrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(appUser.getAuthority().toString()));

		return new User(appUser.getUsername(), appUser.getPassword(), authorities);
	}

	public AppUser registerNewUser(String username, String password) throws AppUserServiceException {
		var optionalUser = appUserRepository.findAppUserByUsername(username);
		if (optionalUser.isPresent())
			throw new AppUserServiceException(ExceptionType.USERNAME_IN_USE);
		var user = new AppUser(null, username, password, Authority.USER);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return appUserRepository.save(user);
	}

	public AppUser saveAppUser(AppUser user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return appUserRepository.save(user);
	}

	public AppUser getUser(String username) throws AppUserServiceException {
		var optionalUser = appUserRepository.findAppUserByUsername(username);
		if (optionalUser.isPresent())
			return optionalUser.get();
		else
			throw new AppUserServiceException(ExceptionType.USERNAME_NOT_EXIST);
	}

	public Collection<AppUser> getUsers() {
		return appUserRepository.findAll();
	}

	public void deleteUserByUsername(String username) throws AppUserServiceException {
		var success = appUserRepository.deleteAppUserByUsername(username);
		if (success == 0)
			throw new AppUserServiceException(ExceptionType.USERNAME_NOT_EXIST);
	}

}
