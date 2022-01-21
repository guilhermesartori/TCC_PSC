package br.ufsc.tsp.service;

import java.util.Map;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.KnetConfiguration;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KnetConfigurationRepository;
import br.ufsc.tsp.service.exception.SystemServiceException;

// TODO delegate finds to appuserservice
@Service
@Transactional
public class SystemConfigurationService {

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private KNetCommunicationService kNetCommunicationService;

	@Autowired
	private KnetConfigurationRepository knetConfigurationRepository;

	@Autowired
	private KeyParameterEncryptor parameterEncryptor;

	private boolean systemIsConfigured = false;

	public AppUser createAdministratorUser(String username, String password) throws SystemServiceException {
		if (appUserRepository.findAppUserByAuthority(Authority.ADMINISTRATOR).isPresent()) {
			throw new SystemServiceException();
		}
		var user = new AppUser(null, username, password, Authority.ADMINISTRATOR);
		var savedUser = appUserService.saveUser(user);
		updateSystemConfiguredState();
		return savedUser;
	}

	public void setKnetConfiguration(Map<String, String> knetParameters, String encryptedAccessKey)
			throws SystemServiceException {
		var knetConfigurations = knetConfigurationRepository.findAll();
		KnetConfiguration knetConfiguration;
		if (knetConfigurations.size() == 0)
			knetConfiguration = new KnetConfiguration();
		else
			knetConfiguration = knetConfigurations.get(0);
		var encryptedParameters = parameterEncryptor.encryptKnetParameters(knetParameters, encryptedAccessKey);
		try {
			kNetCommunicationService.setKnetConfiguration(knetParameters);
		} catch (KNetException e) {
			// TODO PROPER EXCEPTION
			throw new SystemServiceException();
		}
		knetConfiguration.setEncryptedParameters(encryptedParameters);
		knetConfigurationRepository.save(knetConfiguration);
		updateSystemConfiguredState();
	}

	public void loadKnetConfiguration(String encryptedAccessKey) throws SystemServiceException {
		var knetConfigurationList = knetConfigurationRepository.findAll();
		if (knetConfigurationList.size() != 1)
			// TODO PROPER EXCEPTION
			throw new SystemServiceException();
		var knetConfiguration = knetConfigurationList.get(0);
		var encryptedParameters = knetConfiguration.getEncryptedParameters();
		var decryptedParameters = parameterEncryptor.decryptKnetParameters(encryptedParameters, encryptedAccessKey);
		try {
			kNetCommunicationService.setKnetConfiguration(decryptedParameters);
		} catch (KNetException e) {
			// TODO PROPER EXCEPTION
			throw new SystemServiceException();
		}
		updateSystemConfiguredState();
	}

	public void refreshSystemKey() {
		SystemKey.refreshKey();
	}

	public boolean isSystemConfigured() {
		return this.systemIsConfigured;
	}

	public void updateSystemConfiguredState() {
		var temp = true;
		temp = temp && appUserRepository.findAppUserByAuthority(Authority.ADMINISTRATOR).isPresent();
		temp = temp && kNetCommunicationService.isKnetConfigurationLoaded();
	}

}
