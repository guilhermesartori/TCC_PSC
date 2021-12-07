package br.ufsc.tsp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.ufsc.tsp.controller.request.KeyPairGenerationRequest;
import br.ufsc.tsp.controller.request.SignatureRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.controller.response.SignatureResponse;
import br.ufsc.tsp.exception.KeyPairServiceException;
import br.ufsc.tsp.service.KeyPairService;

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
			keyPairService.createKeyPair(username, encodingKey, request.getKeyAlgorithm(), request.getKeyParameter(),
					request.getKeyName());
			return ResponseEntity.created(null).build();
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Exception e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(body);
		}
	}

	@DeleteMapping
	public ResponseEntity<Object> deleteKeyPair(@RequestParam String uniqueIdentifier) {
		try {
			var username = SecurityContextHolder.getContext().getAuthentication().getName();
			var encodingKey = (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
			keyPairService.deleteKeyPair(username, encodingKey, uniqueIdentifier);
			return ResponseEntity.noContent().build();
		} catch (KeyPairServiceException e) {
			var body = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.badRequest().body(body);
		} catch (Exception e) {
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
			var body = new SignatureResponse(signature);
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
