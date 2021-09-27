package br.ufsc.tsp.service;

import java.util.Collection;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.repository.AppUserRepository;

@Service
@Transactional
public class AppUserService {

	private final AppUserRepository appUserRepository;

	@Autowired
	public AppUserService(AppUserRepository appUserRepository) {
		super();
		this.appUserRepository = appUserRepository;
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

}
