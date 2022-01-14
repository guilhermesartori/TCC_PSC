package br.ufsc.tsp.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KnetConfigurationRepository;
import br.ufsc.tsp.service.exception.SystemServiceException;

@Service
@Transactional
public class SystemConfigurationService {

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private KnetConfigurationRepository knetConfigurationRepository;

	@Autowired
	private KeyParameterEncryptor parameterEncryptor;

	private boolean systemIsConfigured = false;

	public AppUser createAdministratorUser(String name, String username, String password)
			throws SystemServiceException {
		if (appUserRepository.findAppUserByAuthorities(Authority.ADMINISTRATOR).isPresent()) {
			throw new SystemServiceException();
		}
		var user = new AppUser(name, username, password, List.of(Authority.ADMINISTRATOR));
		return appUserService.saveUser(user);
	}

	public AppUser createDatabaseAdministratorUser(String name, String username, String password)
			throws SystemServiceException {
		if (appUserRepository.findAppUserByAuthorities(Authority.DB_ADMIN).isPresent()) {
			throw new SystemServiceException();
		}
		var user = new AppUser(name, username, password, List.of(Authority.DB_ADMIN));
		return appUserService.saveUser(user);
	}

	public void setKnetConfiguration(Map<String, String> knetParameters, String encryptedAccessKey)
			throws SystemServiceException {
		var knetConfig = knetConfigurationRepository.findAll().get(0);
		var encryptedParameters = new HashMap<String, String>();
		for (var entry : knetParameters.entrySet()) {
			var encryptedPramater = parameterEncryptor.encrypt(entry.getValue(), encryptedAccessKey);
			encryptedParameters.put(entry.getKey(), encryptedPramater);
		}
		knetConfigurationRepository.save(knetConfig);
		updateSystemConfiguration();
	}

	public void refreshSystemKey() {
		SystemKey.refreshKey();
	}

	public boolean isSystemConfigured() {
		return this.systemIsConfigured;
	}

	public void updateSystemConfiguration() {
		var temp = true;
		temp = temp && appUserRepository.findAppUserByAuthorities(Authority.ADMINISTRATOR).isPresent();
		temp = temp && appUserRepository.findAppUserByAuthorities(Authority.DB_ADMIN).isPresent();
	}

	public void createDatabaseConfiguration(String url, String username, String password)
			throws SystemServiceException {
		// TODO Auto-generated method stub

	}

}
