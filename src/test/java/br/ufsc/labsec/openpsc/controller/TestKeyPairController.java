package br.ufsc.labsec.openpsc.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.fasterxml.jackson.databind.ObjectMapper;

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

import br.ufsc.labsec.openpsc.data.request.KeyPairGenerationRequest;
import br.ufsc.labsec.openpsc.data.request.SignatureRequest;
import br.ufsc.labsec.openpsc.data.request.SignatureVerificationRequest;
import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.data.response.KeyResponse;
import br.ufsc.labsec.openpsc.data.response.SignatureResponse;
import br.ufsc.labsec.openpsc.data.response.SignatureVerificationResponse;
import br.ufsc.labsec.openpsc.entity.KeyPair;
import br.ufsc.labsec.openpsc.service.AppUserService;
import br.ufsc.labsec.openpsc.service.JWTManager;
import br.ufsc.labsec.openpsc.service.KeyPairService;
import br.ufsc.labsec.openpsc.service.ParameterEncryptor;
import br.ufsc.labsec.openpsc.service.SystemConfigurationService;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException.ExceptionType;

@WebMvcTest(KeyPairController.class)
public class TestKeyPairController {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private KeyPairService keyPairService;

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

		@Bean
		public JWTManager jwtManagerBean() {
			return new JWTManager();
		}

		@Bean
		public ParameterEncryptor parameterEncryptorBean() {
			return new ParameterEncryptor();
		}
	
	}

	@BeforeEach
	public void setupConfiguration() {
		when(systemConfigurationService.isSystemConfigured()).thenReturn(true);
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void createKeyPair_success() throws Exception {
		final var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");
		final var keyPair = new KeyPair();
		keyPair.setUniqueIdentifier("test");
		when(keyPairService.createKeyPair(any(), any(), any(), any(), any())).thenReturn(new KeyPair());

		final var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.CREATED.value(), response.getStatus());
		assertNotNull(response.getHeader("Location"));
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void createKeyPair_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");
		final var exception = new KeyPairServiceException(ExceptionType.KEY_NAME_IN_USE);
		when(keyPairService.createKeyPair(any(), any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void createKeyPair_fail_500() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");
		final var exception = new RuntimeException("test");
		when(keyPairService.createKeyPair(any(), any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void createKeyPair_fail_403() throws Exception {
		final var requestBody = new KeyPairGenerationRequest("RSA", "2048", "my_key");

		final var mvcResult = mockMvc.perform(post("/key").contentType(MediaType.APPLICATION_JSON)
				.content(new ObjectMapper().writeValueAsString(requestBody))).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void deleteKeyPair_success() throws Exception {
		final var mvcResult = mockMvc.perform(delete("/key/test")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void deleteKeyPair_fail_403() throws Exception {
		final var mvcResult = mockMvc.perform(delete("/key/test")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void deleteKeyPair_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var exception = new KeyPairServiceException(ExceptionType.KEY_NAME_IN_USE);
		doThrow(exception).when(keyPairService).deleteKeyPair(any(), any(), any());

		final var mvcResult = mockMvc.perform(delete("/key/test")).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void deleteKeyPair_fail_500() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var exception = new RuntimeException("test");
		doThrow(exception).when(keyPairService).deleteKeyPair(any(), any(), any());

		final var mvcResult = mockMvc.perform(delete("/key/test")).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void sign_success() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new SignatureRequest("SHA512", "test");
		final var content = objectMapper.writeValueAsString(requestBody);
		final var signature = new String("test");
		final var keyPair = new KeyPair(null, null, null, "test", null, null);
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenReturn(signature);
		when(keyPairService.getKeyPair(any(), any())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenReturn("test");

		final var mvcResult = mockMvc
				.perform(post("/key/test/sign").contentType(MediaType.APPLICATION_JSON).content(content)).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, SignatureResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(signature, responseBody.getBase64EncodedSignature());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void sign_fail_403() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new SignatureRequest("SHA512", "test");
		final var content = objectMapper.writeValueAsString(requestBody);
		final var signature = "test";
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenReturn(signature);

		final var mvcResult = mockMvc
				.perform(post("/key/test/sign").contentType(MediaType.APPLICATION_JSON).content(content)).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void sign_fail_400() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new SignatureRequest("SHA512", "test");
		final var content = objectMapper.writeValueAsString(requestBody);
		final var exception = new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc
				.perform(post("/key/test/sign").contentType(MediaType.APPLICATION_JSON).content(content)).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void sign_fail_500() throws Exception {
		final var objectMapper = new ObjectMapper();
		final var requestBody = new SignatureRequest("SHA512", "test");
		final var content = objectMapper.writeValueAsString(requestBody);
		final var exception = new RuntimeException("test");
		when(keyPairService.sign(any(), any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc
				.perform(post("/key/test/sign").contentType(MediaType.APPLICATION_JSON).content(content)).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(responseBody.getError(), exception.getMessage());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKey_success() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var publicKey = "publicKey";
		final var objectMapper = new ObjectMapper();
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		when(keyPairService.getKeyPair(any(), any())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key/uniqueIdentifier")).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, KeyResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(keyAlgorithm, responseBody.getKeyAlgorithm());
		assertEquals(uniqueIdentifier, responseBody.getKeyPairUniqueIdentifier());
		assertEquals(publicKey, responseBody.getPublicKey());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void getKey_fail_403() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var publicKey = "publicKey";
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		when(keyPairService.getKeyPair(any(), any())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key/uniqueIdentifier")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKey_fail_400() throws Exception {
		final var publicKey = "publicKey";
		final var exception = new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		when(keyPairService.getKeyPair(any(), any())).thenThrow(exception);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key/uniqueIdentifier")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKey_fail_500() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		final var exception = new RuntimeException();
		when(keyPairService.getKeyPair(any(), any())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(get("/key/uniqueIdentifier")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKeyByKeyName_success() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var publicKey = "publicKey";
		final var objectMapper = new ObjectMapper();
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		when(keyPairService.getKeyPairByKeyName(anyString(), anyString())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key").param("keyName", "keyName")).andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, KeyResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(keyAlgorithm, responseBody.getKeyAlgorithm());
		assertEquals(uniqueIdentifier, responseBody.getKeyPairUniqueIdentifier());
		assertEquals(publicKey, responseBody.getPublicKey());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void getKeyByKeyName_fail_403() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var publicKey = "publicKey";
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		when(keyPairService.getKeyPairByKeyName(anyString(), anyString())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key").param("keyName", "keyName")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKeyByKeyName_fail_400() throws Exception {
		final var publicKey = "publicKey";
		final var exception = new KeyPairServiceException(ExceptionType.KEY_NOT_FOUND);
		when(keyPairService.getKeyPairByKeyName(any(), any())).thenThrow(exception);
		when(keyPairService.getPublicKey(any(), any())).thenReturn(publicKey);

		final var mvcResult = mockMvc.perform(get("/key").param("keyName", "keyName")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = { "USER" })
	@Test
	public void getKeyByKeyName_fail_500() throws Exception {
		final var keyAlgorithm = "keyAlgorithm";
		final var uniqueIdentifier = "uniqueIdentifier";
		final var keyPair = new KeyPair("publicKeyIdentifier", "privateKey", keyAlgorithm, uniqueIdentifier, "keyName",
				null);
		final var exception = new RuntimeException();
		when(keyPairService.getKeyPairByKeyName(any(), any())).thenReturn(keyPair);
		when(keyPairService.getPublicKey(any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(get("/key").param("keyName", "keyName")).andReturn();

		final var response = mvcResult.getResponse();
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void verify_success() throws Exception {
		final var signatureVerificationRequest = new SignatureVerificationRequest();
		signatureVerificationRequest.setBase64EncodedData("test");
		signatureVerificationRequest.setBase64EncodedSignature("test");
		signatureVerificationRequest.setSignatureAlgorithm("SHA256WithRSA");
		final var objectMapper = new ObjectMapper();
		final var content = objectMapper.writeValueAsString(signatureVerificationRequest);
		when(keyPairService.verifySignature(any(), any(), any(), any())).thenReturn(true);

		final var mvcResult = mockMvc.perform(
				post("/key/uniqueIdentifier/verify-signature").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, SignatureVerificationResponse.class);
		assertEquals(HttpStatus.OK.value(), response.getStatus());
		assertEquals(true, responseBody.isValidSignature());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void verify_fail_400() throws Exception {
		final var signatureVerificationRequest = new SignatureVerificationRequest();
		signatureVerificationRequest.setBase64EncodedData("test");
		signatureVerificationRequest.setBase64EncodedSignature("test");
		signatureVerificationRequest.setSignatureAlgorithm("SHA256WithRSA");
		final var objectMapper = new ObjectMapper();
		final var content = objectMapper.writeValueAsString(signatureVerificationRequest);
		final var exception = new KeyPairServiceException();
		when(keyPairService.verifySignature(any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(
				post("/key/uniqueIdentifier/verify-signature").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		assertEquals(exception.getMessage(), responseBody.getError());
	}

	@WithMockUser(username = "test", password = "test", authorities = {})
	@Test
	public void verify_fail_500() throws Exception {
		final var signatureVerificationRequest = new SignatureVerificationRequest();
		signatureVerificationRequest.setBase64EncodedData("test");
		signatureVerificationRequest.setBase64EncodedSignature("test");
		signatureVerificationRequest.setSignatureAlgorithm("SHA256WithRSA");
		final var objectMapper = new ObjectMapper();
		final var content = objectMapper.writeValueAsString(signatureVerificationRequest);
		final var exception = new RuntimeException("test");
		when(keyPairService.verifySignature(any(), any(), any(), any())).thenThrow(exception);

		final var mvcResult = mockMvc.perform(
				post("/key/uniqueIdentifier/verify-signature").contentType(MediaType.APPLICATION_JSON).content(content))
				.andReturn();

		final var response = mvcResult.getResponse();
		final var responseBodyAsString = response.getContentAsString();
		final var responseBody = objectMapper.readValue(responseBodyAsString, ErrorMessageResponse.class);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
		assertEquals(exception.getMessage(), responseBody.getError());
	}
}
