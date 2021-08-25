package br.ufsc.tsp.keypair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.ufsc.tsp.error.ErrorMessage;
import br.ufsc.tsp.keypair.exception.KeyPairDeletionException;
import br.ufsc.tsp.keypair.exception.KeyPairGenerationException;
import br.ufsc.tsp.keypair.exception.SignatureException;
import br.ufsc.tsp.keypair.requestdto.KeyPairGenerationRequest;
import br.ufsc.tsp.keypair.requestdto.SignatureRequest;
import br.ufsc.tsp.keypair.responsedto.SignatureResponse;

@RestController
@RequestMapping(path = "key")
public class KeyPairController {

	private KeyPairService keyPairService;

	/**
	 * @param keyPairService
	 */
	@Autowired
	public KeyPairController(KeyPairService keyPairService) {
		super();
		this.keyPairService = keyPairService;
	}

	@GetMapping
	public ResponseEntity<Object> getKeyPairs() {
		Object body;
		HttpHeaders headers;
		HttpStatus status;

		try {
			body = keyPairService.getKeyPairs();
			headers = new HttpHeaders();
			status = HttpStatus.OK;
		} catch (Exception e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.INTERNAL_SERVER_ERROR;
		}

		return new ResponseEntity<Object>(body, headers, status);
	}

	@PostMapping
	public ResponseEntity<Object> createKeyPair(@RequestBody KeyPairGenerationRequest request) {
		Object body;
		HttpHeaders headers;
		HttpStatus status;

		try {
			keyPairService.createKeyPair(request);
			body = null;
			headers = new HttpHeaders();
			status = HttpStatus.OK;
		} catch (KeyPairGenerationException e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.BAD_REQUEST;
		} catch (Exception e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.INTERNAL_SERVER_ERROR;
		}
		return new ResponseEntity<Object>(body, headers, status);
	}

	@DeleteMapping
	public ResponseEntity<Object> deleteKeyPair(@RequestParam String uniqueIdentifier) {
		Object body;
		HttpHeaders headers;
		HttpStatus status;

		try {
			keyPairService.deleteKeyPair(uniqueIdentifier);
			body = null;
			headers = new HttpHeaders();
			status = HttpStatus.OK;
		} catch (KeyPairDeletionException e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.BAD_REQUEST;
		} catch (Exception e) {
			e.printStackTrace();
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.INTERNAL_SERVER_ERROR;
		}

		return new ResponseEntity<Object>(body, headers, status);
	}

	@PostMapping(path = "sign")
	public ResponseEntity<Object> sign(@RequestBody SignatureRequest request) {
		Object body;
		HttpHeaders headers;
		HttpStatus status;

		try {
			var signature = keyPairService.sign(request);
			body = new SignatureResponse(signature);
			headers = new HttpHeaders();
			status = HttpStatus.OK;
		} catch (SignatureException e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.BAD_REQUEST;
		} catch (Exception e) {
			body = new ErrorMessage(e.getMessage());
			headers = new HttpHeaders();
			status = HttpStatus.INTERNAL_SERVER_ERROR;
		}
		return new ResponseEntity<Object>(body, headers, status);
	}

}
