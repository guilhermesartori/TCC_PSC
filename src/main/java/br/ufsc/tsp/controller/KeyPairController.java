package br.ufsc.tsp.controller;

import java.net.URI;

import javax.websocket.server.PathParam;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.controller.request.SignatureVerificationRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.controller.response.KeyResponse;
import br.ufsc.tsp.controller.response.SignatureResponse;
import br.ufsc.tsp.controller.response.SignatureVerificationResponse;
import br.ufsc.tsp.service.KeyPairService;
import br.ufsc.tsp.service.exception.KeyPairServiceException;

// ADD SYSTEM START ENDPOINTS
@RestController
@RequestMapping(path = "key")
public class KeyPairController {

	private final KeyPairService keyPairService;

	/**
	 * @param keyPairService
	 */
	@Autowired
	public KeyPairController(KeyPairService keyPairService) {
		super();
		this.keyPairService = keyPairService;
	}

	@PostMapping
	public ResponseEntity<Object> createKeyPair(@RequestBody KeyPairGenerationRequest request) {
		try {
			var username = SecurityContextHolder.getContext().getAuthentication().getName();
			var encodingKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			var keyPair = keyPairService.createKeyPair(username, encodingKey, request.getKeyAlgorithm(),
					request.getKeyParameter(), request.getKeyName());
			var pathToCreatedKey = String.format("/key/%d", keyPair.getUniqueIdentifier());
			var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedKey).toUriString();
			var uri = URI.create(uriString);
			return ResponseEntity.created(uri).build();
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@PostMapping(path = "sign")
	public ResponseEntity<Object> sign(@RequestBody SignatureRequest request) {
		try {
			var username = SecurityContextHolder.getContext().getAuthentication().getName();
			var accessKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			var signature = keyPairService.sign(username, accessKey, request.getBase64EncodedData(),
					request.getKeyUniqueIdentifier(), request.getHashingAlgorithm());

			var keyPair = keyPairService.getKeyPair(username, request.getKeyUniqueIdentifier());
			var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), keyPair.getKeyAlgorithm());

			var body = new SignatureResponse(signature, keyPair.getUniqueIdentifier(), publicKey);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@DeleteMapping(path = "{keyUniqueIdentifier}")
	public ResponseEntity<Object> deleteKeyPair(@PathParam("keyUniqueIdentifier") String uniqueIdentifier) {
		try {
			var username = SecurityContextHolder.getContext().getAuthentication().getName();
			var encodingKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			keyPairService.deleteKeyPair(username, encodingKey, uniqueIdentifier);
			return ResponseEntity.noContent().build();
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@GetMapping(path = "{keyUniqueIdentifier}")
	public ResponseEntity<Object> getKey(@PathParam("keyUniqueIdentifier") String keyUniqueIdentifier) {
		try {
			var username = SecurityContextHolder.getContext().getAuthentication().getName();
			var keyPair = keyPairService.getKeyPair(username, keyUniqueIdentifier);
			var keyAlgorithm = keyPair.getKeyAlgorithm();
			var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
			var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm);
			var body = new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@PostMapping(path = "{keyUniqueIdentifier}/verify-signature")
	public ResponseEntity<Object> verify(@PathParam("keyUniqueIdentifier") String keyUniqueIdentifier,
			@RequestBody SignatureVerificationRequest request) {
		try {
			var validSignature = keyPairService.verifySignature(keyUniqueIdentifier, request.getBase64EncodedData(),
					request.getBase64EncodedSignature(), request.getSignatureAlgorithm());
			var body = new SignatureVerificationResponse(validSignature);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Exception e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

}
