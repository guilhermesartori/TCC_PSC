package br.ufsc.tsp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.exception.AppUserServiceException;

@SpringBootTest
public class TestAppUserService {

	private static final String USER_NAME = "test";
	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";

	@Autowired
	private AppUserService appUserService;

	@Test
	public void test_loadUserByUsername_fail() {
		var thrownException = assertThrows(UsernameNotFoundException.class, () -> {
			appUserService.loadUserByUsername(USER_USERNAME);
		});

		assertEquals(String.format("User %s not found", USER_USERNAME), thrownException.getMessage());
	}

	@Test
	public void test_loadUserByUsername_success() throws AppUserServiceException {
		var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		appUserService.saveUser(user);

		try {
			var userDetails = appUserService.loadUserByUsername(USER_USERNAME);

			assertEquals(USER_USERNAME, userDetails.getUsername());
			assertNotNull(userDetails.getUsername());
			assertNotNull(userDetails.getAuthorities());
			assertEquals(0, userDetails.getAuthorities().size());
		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_saveUser_fail() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		final var user2 = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		appUserService.saveUser(user);

		try {
			assertThrows(DataIntegrityViolationException.class, () -> {
				appUserService.saveUser(user2);
			});
		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_saveUser_success() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());

		AppUser savedUser = null;
		try {
			savedUser = appUserService.saveUser(user);

			assertEquals(USER_NAME, savedUser.getName());
			assertEquals(USER_USERNAME, savedUser.getUsername());
			assertNotNull(savedUser.getPassword());
			assertEquals(new ArrayList<>(), savedUser.getAuthorities());

		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_getUser_fail() {
		final var user = appUserService.getUser(USER_USERNAME);
		assertNull(user);
	}

	@Test
	public void test_getUser_success() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		final var savedUser = appUserService.saveUser(user);

		try {
			final var gottenUser = appUserService.getUser(USER_USERNAME);

			assertEquals(savedUser.getName(), gottenUser.getName());
			assertEquals(savedUser.getUsername(), gottenUser.getUsername());
			assertNotNull(gottenUser.getPassword());
			assertEquals(savedUser.getAuthorities().size(), gottenUser.getAuthorities().size());

		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_addRoleToUserByAuthorityEnum() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		appUserService.saveUser(user);

		try {
			appUserService.addRoleToUser(USER_USERNAME, Authority.CREATE_KEY);

			final var gottenUser = appUserService.getUser(USER_USERNAME);
			assertTrue(gottenUser.getAuthorities().contains(Authority.CREATE_KEY));

		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_addRoleToUserByString() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		appUserService.saveUser(user);

		try {
			appUserService.addRoleToUser(USER_USERNAME, "CREATE_KEY");

			final var gottenUser = appUserService.getUser(USER_USERNAME);
			assertTrue(gottenUser.getAuthorities().contains(Authority.CREATE_KEY));

		} finally {
			appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void test_deleteUserByUsername_fail() {
		assertThrows(AppUserServiceException.class, () -> {
			appUserService.deleteUserByUsername(USER_USERNAME);
		});
	}

	@Test
	public void test_deleteUserByUsername_success() {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		appUserService.saveUser(user);

		assertDoesNotThrow(() -> {
			appUserService.deleteUserByUsername(USER_USERNAME);
		});

		final var gottenUser = appUserService.getUser(USER_USERNAME);
		assertNull(gottenUser);
	}

	@Test
	public void test_getUsers() throws AppUserServiceException {
		final var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, new ArrayList<>());
		final var user2 = new AppUser(USER_NAME, USER_USERNAME + "2", USER_PASSWORD, new ArrayList<>());
		final var savedUser = appUserService.saveUser(user);
		final var savedUser2 = appUserService.saveUser(user2);
		
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
