package br.ufsc.tsp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.ufsc.tsp.controller.request.KNetConfigurationRequest;
import br.ufsc.tsp.controller.response.ErrorMessageResponse;
import br.ufsc.tsp.exception.SystemServiceException;
import br.ufsc.tsp.service.SystemService;

@RestController
@RequestMapping(path = "system")
public class SystemConfigurationController {

	@Autowired
	private SystemService systemService;

	@PostMapping("knet")
	public ResponseEntity<Object> createKnetConfiguration(KNetConfigurationRequest request) {
		try {
			systemService.createKnetConfiguration(request.getParameters());
			return ResponseEntity.ok().build();
		} catch (SystemServiceException e) {
			var errorResponse = new ErrorMessageResponse(e.getMessage());
			return ResponseEntity.internalServerError().body(errorResponse);
		}
	}

	@PostMapping("refresh-key")
	public ResponseEntity<Object> refreshSystemKey() {
		return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();
	}

}
