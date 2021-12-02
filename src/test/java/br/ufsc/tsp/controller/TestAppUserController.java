package br.ufsc.tsp.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.domain.AppUser;
import br.ufsc.tsp.domain.enums.Authority;
import br.ufsc.tsp.service.AppUserService;

@WebMvcTest(AppUserController.class)
public class TestAppUserController {

	private static final String USER_NAME = "test";
	private static final String USER_USERNAME = "test";
	private static final String USER_PASSWORD = "test";
	private static final Authority ROLE = Authority.CREATE_KEY;
	private static final List<Authority> ROLES = new ArrayList<>();

	static {
		ROLES.add(ROLE);
	}

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private AppUserService appUserService;

	@WithMockUser(username = "test", password = "test", roles = { "CREATE_KEY" })
	@Test
	public void test_saveUser() throws Exception {
		var user = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, ROLES);
		var savedUser = new AppUser(USER_NAME, USER_USERNAME, USER_PASSWORD, ROLES);
		savedUser.setId(1L);
		Mockito.when(appUserService.saveUser(Mockito.any())).thenReturn(savedUser);
		var mvcResult = mockMvc.perform(post("/user").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(user))).andReturn();
		assertEquals(HttpStatus.CREATED.value(), mvcResult.getResponse().getStatus());
	}

}
