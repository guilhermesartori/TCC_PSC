package br.ufsc.tsp.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.service.exception.AppUserServiceException;
import br.ufsc.tsp.service.exception.KNetCommunicationServiceException;
import br.ufsc.tsp.service.exception.SystemServiceException;
import br.ufsc.tsp.service.exception.SystemServiceException.ExceptionType;

@SpringBootTest
public class TestSystemService {

	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";
	private static final String EXCEPTION_MESSAGE = "test";

	@Autowired
	private SystemConfigurationService systemConfigurationService;

	@Autowired
	private AppUserService appUserService;

	@Autowired
	private ParameterEncryptor parameterEncryptor;

	@MockBean
	private KNetCommunicationService kNetCommunicationService;

	private static Map<String, String> knetParameters;

	static {
		knetParameters = new HashMap<String, String>();
		knetParameters.put("ADDRESS_CONN", "192.168.66.20");
		knetParameters.put("PORT_CONN", "60055");
		knetParameters.put("USERNAME", "test_user");
		knetParameters.put("PW", "2m;z#MkD-tcc-guilherme");
		knetParameters.put("MAX_CONNECTIONS", "1");
	}

	@Test
	public void createAdministratorUser_success() throws SystemServiceException, AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = systemConfigurationService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

			assertEquals(USER_USERNAME, savedUser.getUsername());
			assertNotNull(savedUser.getPassword());
			assertEquals(Authority.ADMINISTRATOR, savedUser.getAuthority());

		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void createAdministratorUser_fail() throws SystemServiceException, AppUserServiceException {
		AppUser savedUser = null;
		try {
			savedUser = systemConfigurationService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

			assertThrows(SystemServiceException.class, () -> {
				systemConfigurationService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);
			});
		} finally {
			if (savedUser != null)
				appUserService.deleteUserByUsername(USER_USERNAME);
		}
	}

	@Test
	public void loadKnetConfiguration_success()
			throws SystemServiceException, KNetException, KNetCommunicationServiceException {
		final var accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
		final var savedKnetConfiguration = systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);
		doNothing().when(kNetCommunicationService).loadKnetConfiguration(any());

		assertDoesNotThrow(() -> {
			systemConfigurationService.loadKnetConfiguration(accessKey);

		});

		systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);
	}

	@Test
	public void loadKnetConfiguration_fail_KNetException()
			throws SystemServiceException, KNetException, KNetCommunicationServiceException {
		final var accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
		final var savedKnetConfiguration = systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);
		final var exception = new KNetException(EXCEPTION_MESSAGE, new Exception());
		doThrow(exception).when(kNetCommunicationService).loadKnetConfiguration(any());

		final var thrownException = assertThrows(SystemServiceException.class, () -> {
			systemConfigurationService.loadKnetConfiguration(accessKey);

			systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);
		});

		systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);

		final var expectedException = new SystemServiceException(ExceptionType.INVALID_KNET_CONFIG);
		assertEquals(expectedException.getMessage(), thrownException.getMessage());
	}

	@Test
	public void loadKnetConfiguration_fail_KNetCommunicationServiceException()
			throws SystemServiceException, KNetException, KNetCommunicationServiceException {
		final var accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
		final var savedKnetConfiguration = systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);
		final var exception = new KNetCommunicationServiceException();
		doThrow(exception).when(kNetCommunicationService).loadKnetConfiguration(any());

		final var thrownException = assertThrows(SystemServiceException.class, () -> {
			systemConfigurationService.loadKnetConfiguration(accessKey);

			systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);
		});

		systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);

		final var expectedException = new SystemServiceException(exception.getMessage());
		assertEquals(expectedException.getMessage(), thrownException.getMessage());

	}

	@Test
	public void setKnetConfiguration_success()
			throws SystemServiceException, KNetException, KNetCommunicationServiceException {
		final var accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
		doNothing().when(kNetCommunicationService).setKnetConfiguration(any());

		assertDoesNotThrow(() -> {
			final var savedKnetConfiguration = systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);

			systemConfigurationService.deleteKnetConfiguration(savedKnetConfiguration);
		});

	}

	@Test
	public void setKnetConfiguration_fail()
			throws SystemServiceException, KNetException, KNetCommunicationServiceException {
		final var accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
		final var exception = new KNetException(EXCEPTION_MESSAGE, new Exception());
		doThrow(exception).when(kNetCommunicationService).setKnetConfiguration(any());

		final var thrownException = assertThrows(SystemServiceException.class, () -> {
			systemConfigurationService.setKnetConfiguration(knetParameters, accessKey);
		});

		final var expectedException = new SystemServiceException(ExceptionType.INVALID_KNET_CONFIG);
		assertEquals(expectedException.getMessage(), thrownException.getMessage());

	}

	@Test
	public void refreshSystemKey() {
		final var systemKey = SystemKey.getKey();

		systemConfigurationService.refreshSystemKey();

		final var newSystemKey = SystemKey.getKey();
		assertFalse(Arrays.equals(systemKey, newSystemKey));
	}

	@Test
	public void updateSystemConfiguredState_notConfigured() {
		final var isConfigured = systemConfigurationService.isSystemConfigured();
		when(kNetCommunicationService.isKnetConfigurationLoaded()).thenReturn(false);

		systemConfigurationService.updateSystemConfiguredState();

		final var isConfiguredUpdated = systemConfigurationService.isSystemConfigured();
		assertFalse(isConfigured);
		assertEquals(isConfigured, isConfiguredUpdated);
	}

	@Test
	public void updateSystemConfiguredState_onlyKnetConfigured() {
		final var isConfigured = systemConfigurationService.isSystemConfigured();
		when(kNetCommunicationService.isKnetConfigurationLoaded()).thenReturn(true);

		systemConfigurationService.updateSystemConfiguredState();

		final var isConfiguredUpdated = systemConfigurationService.isSystemConfigured();
		assertFalse(isConfigured);
		assertEquals(isConfigured, isConfiguredUpdated);
	}

	@Test
	public void updateSystemConfiguredState_onlyAdminConfigured()
			throws AppUserServiceException, SystemServiceException {
		final var isConfigured = systemConfigurationService.isSystemConfigured();
		when(kNetCommunicationService.isKnetConfigurationLoaded()).thenReturn(false);
		systemConfigurationService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

		systemConfigurationService.updateSystemConfiguredState();

		final var isConfiguredUpdated = systemConfigurationService.isSystemConfigured();
		appUserService.deleteUserByUsername(USER_USERNAME);
		assertFalse(isConfigured);
		assertEquals(isConfigured, isConfiguredUpdated);
	}
	
	@Test
	public void updateSystemConfiguredState_allConfiguration()
			throws AppUserServiceException, SystemServiceException {
		final var isConfigured = systemConfigurationService.isSystemConfigured();
		when(kNetCommunicationService.isKnetConfigurationLoaded()).thenReturn(true);
		systemConfigurationService.createAdministratorUser(USER_USERNAME, USER_PASSWORD);

		systemConfigurationService.updateSystemConfiguredState();

		final var isConfiguredUpdated = systemConfigurationService.isSystemConfigured();
		appUserService.deleteUserByUsername(USER_USERNAME);
		assertFalse(isConfigured);
		assertNotEquals(isConfigured, isConfiguredUpdated);
	}

}
