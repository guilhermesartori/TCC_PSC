package br.ufsc.tsp.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

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
import br.ufsc.tsp.controller.request.RoleToUserForm;
import br.ufsc.tsp.entity.AppUser;
import br.ufsc.tsp.entity.enums.Authority;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.SystemConfigurationService;

@WebMvcTest(AppUserController.class)
public class TestAppUserController {

	private static final String USER_NAME_1 = "test";
	private static final String USER_NAME_2 = "test2";
	private static final String USER_USERNAME_1 = "test";
	private static final String USER_USERNAME_2 = "test";
	private static final String USER_PASSWORD_1 = "test";
	private static final String USER_PASSWORD_2 = "test";
	private static final Authority ROLE = Authority.USER;
	private static final List<Authority> ROLES = new ArrayList<>();

	static {
		ROLES.add(ROLE);
	}

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
	public void saveUser_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var user = new RegisterUserRequest(USER_NAME_1, USER_USERNAME_1, USER_PASSWORD_1);
		var content = objectMapper.writeValueAsString(user);
		var savedUser = new AppUser(USER_NAME_1, USER_USERNAME_1, USER_PASSWORD_1, ROLES);
		savedUser.setId(1L);
		when(appUserService.registerNewUser(any(), any(), any())).thenReturn(savedUser);

		var mvcResult = mockMvc.perform(post("/user").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, AppUser.class);

		assertEquals(HttpStatus.CREATED.value(), response.getStatus());
		assertEquals(savedUser, responseBody);
		assertNotNull(response.getHeader("Location"));
	}

	// TODO saveUser_fail

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void getUsers_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var user1 = new AppUser(USER_NAME_1, USER_USERNAME_1, USER_PASSWORD_1, ROLES);
		var user2 = new AppUser(USER_NAME_2, USER_USERNAME_2, USER_PASSWORD_2, ROLES);
		Collection<AppUser> users = List.of(user1, user2);
		when(appUserService.getUsers()).thenReturn(users);

		var mvcResult = mockMvc.perform(get("/user")).andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, AppUser[].class);
		var appUserSet = Set.of(responseBody);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(2, responseBody.length);
		assertTrue(appUserSet.contains(user1));
		assertTrue(appUserSet.contains(user1));
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void getUsers_fail_403() throws Exception {
		var user1 = new AppUser(USER_NAME_1, USER_USERNAME_1, USER_PASSWORD_1, ROLES);
		var user2 = new AppUser(USER_NAME_2, USER_USERNAME_2, USER_PASSWORD_2, ROLES);
		Collection<AppUser> users = List.of(user1, user2);
		when(appUserService.getUsers()).thenReturn(users);

		var mvcResult = mockMvc.perform(get("/user")).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "ADMINISTRATOR" })
	@Test
	public void addRoleToUser_success() throws Exception {
		var roleToUserForm = new RoleToUserForm("ADMINISTRATOR");

		var mvcResult = mockMvc.perform(post("/user/teste/authority").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(roleToUserForm))).andReturn();

		assertEquals(HttpStatus.OK.value(), mvcResult.getResponse().getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void addRoleToUser_fail_403() throws Exception {
		var roleToUserForm = new RoleToUserForm("CREATE_KEY");

		var mvcResult = mockMvc.perform(post("/user/teste/authority").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(roleToUserForm))).andReturn();

		assertEquals(HttpStatus.FORBIDDEN.value(), mvcResult.getResponse().getStatus());
	}

}
