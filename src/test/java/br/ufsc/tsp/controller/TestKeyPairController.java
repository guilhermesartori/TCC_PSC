package br.ufsc.tsp.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.controller.response.SignatureResponse;
import br.ufsc.tsp.service.AppUserService;
import br.ufsc.tsp.service.KeyPairService;

@WebMvcTest(KeyPairController.class)
public class TestKeyPairController {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private KeyPairService keyPairService;

	@MockBean
	private AppUserService appUserService;

	@WithMockUser(username = "test", password = "test", authorities = { "CREATE_KEY" })
	@Test
	public void createKeyPair_success() throws Exception {
		var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");

		var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.CREATED.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void createKeyPair_fail_403() throws Exception {
		var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");

		var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "DELETE_KEY" })
	@Test
	public void deleteKeyPair_success() throws Exception {
		var mvcResult = mockMvc.perform(delete("/key").queryParam("uniqueIdentifier", "test")).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void deleteKeyPair_fail_403() throws Exception {
		var mvcResult = mockMvc.perform(delete("/key").queryParam("uniqueIdentifier", "test")).andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "SIGN" })
	@Test
	public void sign_success() throws Exception {
		var objectMapper = new ObjectMapper();
		var requestBody = new SignatureRequest("test", "SHA512", "test");
		var content = objectMapper.writeValueAsString(requestBody);
		var signature = "test";
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenReturn(signature);

		var mvcResult = mockMvc.perform(post("/key/sign").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		var responseBodyAsString = response.getContentAsString();
		var responseBody = objectMapper.readValue(responseBodyAsString, SignatureResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(signature, responseBody.getBase64Signature());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void sign_fail_403() throws Exception {
		var objectMapper = new ObjectMapper();
		var requestBody = new SignatureRequest("test", "SHA512", "test");
		var content = objectMapper.writeValueAsString(requestBody);
		var signature = "test";
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenReturn(signature);

		var mvcResult = mockMvc.perform(post("/key/sign").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

}