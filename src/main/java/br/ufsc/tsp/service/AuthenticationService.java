package br.ufsc.tsp.service;

import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.domain.Role;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.utility.JWTManager;

@Service
@Transactional
public class AuthenticationService {

	private final AppUserRepository appUserRepository;

	/**
	 * @param appUserRepository
	 */
	@Autowired
	public AuthenticationService(AppUserRepository appUserRepository) {
		super();
		this.appUserRepository = appUserRepository;
	}

	public String generateNewAccessToken(String refreshToken, String issuer) {
		var jwtManager = new JWTManager();
		var decodedJwtManager = jwtManager.decode(refreshToken);
		var username = decodedJwtManager.getUsername();
		var user = appUserRepository.findByUsername(username);
		var roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
		var accessToken = jwtManager.createAccessToken(username, issuer, roles);
		return accessToken;
	}

}
