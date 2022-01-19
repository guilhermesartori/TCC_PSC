package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.service.exception.AppUserServiceException;
import br.ufsc.tsp.service.exception.SystemServiceException;

@SpringBootTest
public class TestSystemService {

	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";

	@Autowired
	private SystemConfigurationService systemService;

	@Autowired
	private AppUserService appUserService;

	@Test
	public void test_createAdministratorUser_success() throws SystemServiceException, AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = systemService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

			assertEquals(USER_USERNAME, savedUser.getUsername());
			assertNotNull(savedUser.getPassword());
			assertEquals(Authority.ADMINISTRATOR, savedUser.getAuthority());

		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_createAdministratorUser_fail() throws SystemServiceException, AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = systemService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

			assertThrows(SystemServiceException.class, () -> {
				systemService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);
			});
		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

}
