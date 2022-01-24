package br.ufsc.tsp.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.Collection;
import java.util.List;

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

import br.ufsc.tsp.controller.request.RegisterUserRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.controller.response.UserResponse;
import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.SystemConfigurationService;
import br.ufsc.tsp.service.exception.AppUserServiceException;
import br.ufsc.tsp.service.exception.AppUserServiceException.ExceptionType;

@WebMvcTest(AppUserController.class)
public class TestAppUserController {

	private static final String USER_USERNAME_1 = "test";
	private static final String USER_USERNAME_2 = "test";
	private static final String USER_PASSWORD_1 = "test";
	private static final String USER_PASSWORD_2 = "test";
	private static final Authority AUTHORITY = Authority.USER;

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private AppUserService appUserService;

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

	@Test
	public void registerUser_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		var content = objectMapper.writeValueAsString(user);
		var savedUser = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		savedUser.setId(1L);
		when(appUserService.registerNewUser(any(), any())).thenReturn(savedUser);

		var mvcResult = mockMvc.perform(post("/user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, AppUser.class);

		assertEquals(HttpStatus.CREATED.value(), response.getStatus());
		assertEquals(savedUser, responseBody);
		assertNotNull(response.getHeader("Location"));
	}

	@Test
	public void registerUser_fail_usernameInUse() throws Exception {
		var objectMapper = new ObjectMapper();
		var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		var content = objectMapper.writeValueAsString(user);
		var savedUser = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		savedUser.setId(1L);
		var exception = new AppUserServiceException(ExceptionType.USERNAME_IN_USE);

		when(appUserService.registerNewUser(any(), any())).thenThrow(exception);

		var mvcResult = mockMvc.perform(post("/user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);

		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(exception.getMessage(), responseBody.getError());
	}

	@Test
	public void registerUser_fail_internalError() throws Exception {
		var objectMapper = new ObjectMapper();
		var user = new RegisterUserRequest(USER_USERNAME_1, USER_PASSWORD_1);
		var content = objectMapper.writeValueAsString(user);
		var savedUser = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		savedUser.setId(1L);
		var exception = new RuntimeException();

		when(appUserService.registerNewUser(any(), any())).thenThrow(exception);

		var mvcResult = mockMvc.perform(post("/user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(ErrorMessageResponse.DEFAULT_ERROR, responseBody.getError());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void getUsers_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var user1 = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		var user2 = new AppUser(USER_USERNAME_2, USER_PASSWORD_2, AUTHORITY);
		Collection<AppUser> users = List.of(user1, user2);
		when(appUserService.getUsers()).thenReturn(users);

		var mvcResult = mockMvc.perform(get("/user")).andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, AppUser[].class);
		var appUserSet = List.of(responseBody);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(2, responseBody.length);
		assertTrue(appUserSet.contains(user1));
		assertTrue(appUserSet.contains(user1));
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void getUsers_fail_403() throws Exception {
		var user1 = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		var user2 = new AppUser(USER_USERNAME_2, USER_PASSWORD_2, AUTHORITY);
		Collection<AppUser> users = List.of(user1, user2);
		when(appUserService.getUsers()).thenReturn(users);

		var mvcResult = mockMvc.perform(get("/user")).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void getUser_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var user = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		when(appUserService.getUser(any())).thenReturn(user);

		var mvcResult = mockMvc.perform(get("/user/test")).andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, UserResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(responseBody.getUsername(), user.getUsername());
		assertEquals(responseBody.getAuthority(), user.getAuthority().name());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void getUser_fail_403() throws Exception {
		var user = new AppUser(USER_USERNAME_1, USER_PASSWORD_1, AUTHORITY);
		when(appUserService.getUser(any())).thenReturn(user);

		var mvcResult = mockMvc.perform(get("/user/test")).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void getUser_fail_400() throws Exception {
		var objectMapper = new ObjectMapper();
		var exception = new AppUserServiceException(ExceptionType.USERNAME_NOT_EXIST);
		when(appUserService.getUser(any())).thenThrow(exception);

		var mvcResult = mockMvc.perform(get("/user/test")).andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(exception.getMessage(), responseBody.getError());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void getUser_fail_500() throws Exception {
		var objectMapper = new ObjectMapper();
		var exception = new RuntimeException();
		when(appUserService.getUser(any())).thenThrow(exception);

		var mvcResult = mockMvc.perform(get("/user/test")).andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(ErrorMessageResponse.DEFAULT_ERROR, responseBody.getError());
	}

}
