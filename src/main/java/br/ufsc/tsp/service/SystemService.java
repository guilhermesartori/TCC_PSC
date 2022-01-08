package br.ufsc.tsp.service;

import java.util.List;
import java.util.Map;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.service.exception.SystemServiceException;
import br.ufsc.tsp.service.utility.SystemKey;

@Service
@Transactional
public class SystemService {

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private KNetCommunicationService keyManager;

	public void createKnetConfiguration(Map<String, String> knetParameters) throws SystemServiceException {
		try {
			keyManager.setKnetConfiguration(knetParameters);
		} catch (KNetException e) {
			throw new SystemServiceException();
		}
	}

	public AppUser createAdministratorUser(String name, String username, String password)
			throws SystemServiceException {
		if (appUserRepository.findAppUserByAuthorities(Authority.ADMINISTRATOR).isPresent()) {
			throw new SystemServiceException();
		}
		var user = new AppUser(name, username, password, List.of(Authority.ADMINISTRATOR));
		return appUserService.saveUser(user);
	}

	public void refreshSystemKey() {
		SystemKey.refreshKey();
	}

}
