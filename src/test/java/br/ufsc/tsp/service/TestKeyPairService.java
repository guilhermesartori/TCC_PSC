package br.ufsc.tsp.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.exception.KeyPairDeletionException;
import br.ufsc.tsp.exception.KeyPairGenerationException;
import br.ufsc.tsp.repository.AppUserRepository;

public class TestKeyPairService {

	@Autowired
	private KeyPairService keyPairService;

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private AppUserRepository appUserRepository;

	@Test
	public void test_createKeyPair_RSA_2048()
			throws KeyPairGenerationException, KeyPairDeletionException, KNetException {
		appUserService.saveUser(new AppUser(null, "test", "test", "test", null));
		var keyCreationRequest = new KeyPairGenerationRequest("RSA", "2048");

		var keyPair = keyPairService.createKeyPair("test", null, keyCreationRequest);

		appUserRepository.deleteByUsername("test");
		keyPairService.deleteKeyPair("test", null, keyPair.getUniqueIdentifier());
	}

}
