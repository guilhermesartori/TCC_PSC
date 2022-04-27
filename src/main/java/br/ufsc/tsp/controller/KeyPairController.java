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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import br.ufsc.tsp.data.request.KeyPairGenerationRequest;
import br.ufsc.tsp.data.request.SignatureRequest;
import br.ufsc.tsp.data.request.SignatureVerificationRequest;
import br.ufsc.tsp.data.response.ErrorMessageResponse;
import br.ufsc.tsp.data.response.KeyResponse;
import br.ufsc.tsp.data.response.SignatureResponse;
import br.ufsc.tsp.data.response.SignatureVerificationResponse;
import br.ufsc.tsp.service.KeyPairService;
import br.ufsc.tsp.service.exception.KeyPairServiceException;

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

	@GetMapping
	public ResponseEntity<Object> getKeyByKeyName(@RequestParam("keyName") String keyName) {
		try {
			final var username = SecurityContextHolder.getContext().getAuthentication().getName();
			final var keyPair = keyPairService.getKeyPairByKeyName(username, keyName);
			final var keyAlgorithm = keyPair.getKeyAlgorithm();
			final var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
			final var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm);
			final var body = new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}
	
	@PostMapping
	public ResponseEntity<Object> createKeyPair(@RequestBody KeyPairGenerationRequest request) {
		try {
			final var username = SecurityContextHolder.getContext().getAuthentication().getName();
			final var encodingKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			final var keyPair = keyPairService.createKeyPair(username, encodingKey, request.getKeyAlgorithm(),
					request.getKeyParameter(), request.getKeyName());
			final var pathToCreatedKey = String.format("/key/%d", keyPair.getUniqueIdentifier());
			final var uriString = ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedKey)
					.toUriString();
			final var uri = URI.create(uriString);
			return ResponseEntity.created(uri).build();
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@PostMapping(path = "{keyUniqueIdentifier}/sign")
	public ResponseEntity<Object> sign(@RequestBody SignatureRequest request,
			@PathParam("keyUniqueIdentifier") String uniqueIdentifier) {
		try {
			final var username = SecurityContextHolder.getContext().getAuthentication().getName();
			final var accessKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			final var signature = keyPairService.sign(username, accessKey, request.getBase64EncodedData(),
					uniqueIdentifier, request.getHashingAlgorithm());

			final var keyPair = keyPairService.getKeyPair(username, uniqueIdentifier);
			final var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), keyPair.getKeyAlgorithm());

			final var body = new SignatureResponse(signature, uniqueIdentifier, publicKey);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@DeleteMapping(path = "{keyUniqueIdentifier}")
	public ResponseEntity<Object> deleteKeyPair(@PathParam("keyUniqueIdentifier") String uniqueIdentifier) {
		try {
			final var username = SecurityContextHolder.getContext().getAuthentication().getName();
			final var encodingKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			keyPairService.deleteKeyPair(username, encodingKey, uniqueIdentifier);
			return ResponseEntity.noContent().build();
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@GetMapping(path = "{keyUniqueIdentifier}")
	public ResponseEntity<Object> getKey(@PathParam("keyUniqueIdentifier") String keyUniqueIdentifier) {
		try {
			final var username = SecurityContextHolder.getContext().getAuthentication().getName();
			final var keyPair = keyPairService.getKeyPair(username, keyUniqueIdentifier);
			final var keyAlgorithm = keyPair.getKeyAlgorithm();
			final var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
			final var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm);
			final var body = new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Throwable e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@PostMapping(path = "{keyUniqueIdentifier}/verify-signature")
	public ResponseEntity<Object> verify(@PathParam("keyUniqueIdentifier") String keyUniqueIdentifier,
			@RequestBody SignatureVerificationRequest request) {
		try {
			final var validSignature = keyPairService.verifySignature(keyUniqueIdentifier,
					request.getBase64EncodedData(), request.getBase64EncodedSignature(),
					request.getSignatureAlgorithm());
			final var body = new SignatureVerificationResponse(validSignature);
			return ResponseEntity.ok().body(body);
		} catch (KeyPairServiceException e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Exception e) {
			final var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

}
