package br.ufsc.tsp.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import java.util.HashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.request.KNetConfigurationRequest;
import br.ufsc.tsp.controller.request.RegisterUserRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.controller.response.UserResponse;
import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.repository.AppUserRepository;
import br.ufsc.tsp.repository.KnetConfigurationRepository;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.KNetCommunicationService;
import br.ufsc.tsp.service.ParameterEncryptor;
import br.ufsc.tsp.service.SystemConfigurationService;
import br.ufsc.tsp.service.exception.SystemServiceException;

@WebMvcTest(SystemConfigurationController.class)
public class TestSystemController {

	private static final String USER_USERNAME_1 = "test";
	private static final String USER_PASSWORD_1 = "test";
	private static final Authority AUTHORITY = Authority.ADMINISTRATOR;

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private AppUserService appUserService;

	@MockBean
	private AppUserRepository appUserRepository;

	@MockBean
	private KNetCommunicationService kNetCommunicationService;

	@MockBean
	private KnetConfigurationRepository knetConfigurationRepository;

	@MockBean
	private ParameterEncryptor parameterEncryptor;

	@MockBean
	private SystemConfigurationService systemConfigurationService;

	@TestConfiguration
	static class TestConfig {
		@Bean
		public PasswordEncoder passwordEncoderBean() {
			return new BCryptPasswordEncoder();
		}
	}

	@BeforeEach
	public void setupConfiguration() {
		when(systemConfigurationService.isSystemConfigured()).thenReturn(true);
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void createSystemAdmin_success() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		final var content = objectMapper.writeValueAsString(user);
		final var savedUser = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		savedUser.setId(1L);
		when(systemConfigurationService.createAdministratorUser(any(), any())).thenReturn(savedUser);

		final var mvcResult = mockMvc
				.perform(post("/system/admin-user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, UserResponse.class);
		assertEquals(response.getStatus(), HttpStatus.CREATED.value());
		assertNotNull(response.getHeader("Location"));
		assertEquals(savedUser.getUsername(), responseBody.getUsername());
		assertEquals(savedUser.getAuthority().name(), responseBody.getAuthority());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void createSystemAdmin_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		final var content = objectMapper.writeValueAsString(user);
		final var exception = new SystemServiceException();
		when(systemConfigurationService.createAdministratorUser(any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc
				.perform(post("/system/admin-user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(response.getStatus(), HttpStatus.BAD_REQUEST.value());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void createSystemAdmin_fail_500() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		final var content = objectMapper.writeValueAsString(user);
		final var exception = new RuntimeException();
		when(systemConfigurationService.createAdministratorUser(any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc
				.perform(post("/system/admin-user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void setKnetConfiguration_success() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var kNetConfigurationRequest = new KNetConfigurationRequest(new HashMap<String, String>());
		final var content = objectMapper.writeValueAsString(kNetConfigurationRequest);
		when(systemConfigurationService.setKnetConfiguration(any(), any())).thenReturn(null);

		final var mvcResult = mockMvc
				.perform(put("/system/knet-config").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.OK.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void setKnetConfiguration_fail_403() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var kNetConfigurationRequest = new KNetConfigurationRequest(new HashMap<String, String>());
		final var content = objectMapper.writeValueAsString(kNetConfigurationRequest);
		when(systemConfigurationService.setKnetConfiguration(any(), any())).thenReturn(null);

		final var mvcResult = mockMvc
				.perform(put("/system/knet-config").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.FORBIDDEN.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void setKnetConfiguration_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var kNetConfigurationRequest = new KNetConfigurationRequest(new HashMap<String, String>());
		final var content = objectMapper.writeValueAsString(kNetConfigurationRequest);
		final var exception = new SystemServiceException();
		doThrow(exception).when(systemConfigurationService).setKnetConfiguration(any(), any());

		final var mvcResult = mockMvc
				.perform(put("/system/knet-config").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(response.getStatus(), HttpStatus.BAD_REQUEST.value());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void setKnetConfiguration_fail_500() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var kNetConfigurationRequest = new KNetConfigurationRequest(new HashMap<String, String>());
		final var content = objectMapper.writeValueAsString(kNetConfigurationRequest);
		final var exception = new RuntimeException();
		doThrow(exception).when(systemConfigurationService).setKnetConfiguration(any(), any());

		final var mvcResult = mockMvc
				.perform(put("/system/knet-config").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void loadKnetConfiguration_success() throws Exception {
		doNothing().when(systemConfigurationService).loadKnetConfiguration(any());

		final var mvcResult = mockMvc.perform(post("/system/knet-config/load")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.OK.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void loadKnetConfiguration_fail_403() throws Exception {
		doNothing().when(systemConfigurationService).loadKnetConfiguration(any());

		final var mvcResult = mockMvc.perform(post("/system/knet-config/load")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.FORBIDDEN.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void loadKnetConfiguration_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var exception = new SystemServiceException();
		doThrow(exception).when(systemConfigurationService).loadKnetConfiguration(any());

		final var mvcResult = mockMvc.perform(post("/system/knet-config/load")).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(response.getStatus(), HttpStatus.BAD_REQUEST.value());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void loadKnetConfiguration_fail_500() throws Exception {
		final var exception = new RuntimeException();
		doThrow(exception).when(systemConfigurationService).loadKnetConfiguration(any());

		final var mvcResult = mockMvc.perform(post("/system/knet-config/load")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void refreshSystemKey_success() throws Exception {
		doNothing().when(systemConfigurationService).refreshSystemKey();

		final var mvcResult = mockMvc.perform(post("/system/refresh-key")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.OK.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void refreshSystemKey_fail_403() throws Exception {
		doNothing().when(systemConfigurationService).refreshSystemKey();

		final var mvcResult = mockMvc.perform(post("/system/refresh-key")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.FORBIDDEN.value());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void refreshSystemKey_fail_500() throws Exception {
		final var exception = new RuntimeException();
		doThrow(exception).when(systemConfigurationService).refreshSystemKey();

		final var mvcResult = mockMvc.perform(post("/system/refresh-key")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(response.getStatus(), HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

}
