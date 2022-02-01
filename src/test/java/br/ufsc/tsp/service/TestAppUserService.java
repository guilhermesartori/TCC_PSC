package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.service.exception.AppUserServiceException;

@SpringBootTest
public class TestAppUserService {

	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";

	@Autowired
	private AppUserService appUserService;

	@Test
	public void loadUserByUsername_fail() {
		var thrownException = assertThrows(UsernameNotFoundException.class, () -> {
			appUserService.loadUserByUsername(USER_USERNAME);
		});

		assertEquals(String.format("User %s not found", USER_USERNAME), thrownException.getMessage());
	}

	@Test
	public void loadUserByUsername_success() throws AppUserServiceException {
		appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);

		try {
			var userDetails = appUserService.loadUserByUsername(USER_USERNAME);

			assertEquals(USER_USERNAME, userDetails.getUsername());
			assertNotNull(userDetails.getUsername());
			assertNotNull(userDetails.getAuthorities());
			assertEquals(1, userDetails.getAuthorities().size());
		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void registerNewUser_fail() throws AppUserServiceException {
		appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);

		try {
			assertThrows(AppUserServiceException.class, () -> {
				appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);
			});
		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void registerNewUser_success() throws AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);

			assertEquals(USER_USERNAME, savedUser.getUsername());
			assertNotNull(savedUser.getPassword());
			assertEquals(Authority.USER, savedUser.getAuthority());

		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void saveAppUser() throws AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = appUserService.saveAppUser(new AppUser(USER_USERNAME, USER_PASSWORD, Authority.USER));

			assertEquals(USER_USERNAME, savedUser.getUsername());
			assertNotNull(savedUser.getPassword());
			assertEquals(Authority.USER, savedUser.getAuthority());

		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void getUser_fail() {
		assertThrows(AppUserServiceException.class, () -> {
			appUserService.getUser(USER_USERNAME);
		});
	}

	@Test
	public void getUser_success() throws AppUserServiceException {
		final var savedUser = appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);

		try {
			final var gottenUser = appUserService.getUser(USER_USERNAME);

			assertEquals(savedUser.getUsername(), gottenUser.getUsername());
			assertNotNull(gottenUser.getPassword());
			assertEquals(savedUser.getAuthority(), gottenUser.getAuthority());

		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void deleteUserByUsername_fail() {
		assertThrows(AppUserServiceException.class, () -> {
			appUserService.deleteUserByUsername(USER_USERNAME);
		});
	}

	@Test
	public void deleteUserByUsername_success() throws AppUserServiceException {
		appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);

		assertDoesNotThrow(() -> {
			appUserService.deleteUserByUsername(USER_USERNAME);
		});

		assertThrows(AppUserServiceException.class, () -> {
			appUserService.getUser(USER_USERNAME);
		});

	}

	@Test
	public void getUsers() throws AppUserServiceException {
		final var savedUser = appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);
		final var savedUser2 = appUserService.registerNewUser(USER_USERNAME + "2", USER_PASSWORD);

		try {
			final var users = appUserService.getUsers();

			assertEquals(2, users.size());
			assertTrue(users.contains(savedUser));
			assertTrue(users.contains(savedUser2));
		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
			appUserService.deleteUserByUsername(USER_USERNAME + "2");
		}
	}

}
