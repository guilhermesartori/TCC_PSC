package br.ufsc.tsp.service;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.exception.KeyPairServiceException;
import br.ufsc.tsp.service.utility.KeyParameterEncryptor;

@SpringBootTest
public class TestKeyPairService {

	@Autowired
	private KeyPairService keyPairService;

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private KeyParameterEncryptor keyParameterEncryptor;

	@Test
	public void test_createKeyPair_RSA_2048() throws KeyPairServiceException, KNetException {
		var authorities = new ArrayList<Authority>();
		authorities.add(Authority.CREATE_KEY);
		var user = new AppUser(1L, "test", "test", "test", authorities);
		appUserService.saveUser(user);
		var accessKey = keyParameterEncryptor.encryptKey("password");

		var keyPair = keyPairService.createKeyPair("test", accessKey, "RSA", "2048", "test_createKeyPair_RSA_2048");

		keyPairService.deleteKeyPair("test", accessKey, keyPair.getUniqueIdentifier());
		appUserService.deleteUserByUsername("test");
	}

}
