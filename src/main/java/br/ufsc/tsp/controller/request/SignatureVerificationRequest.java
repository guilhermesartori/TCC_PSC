package br.ufsc.tsp.controller.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignatureVerificationRequest {

	private String base64EncodedData;
	private String base64EncodedSignature;
	
}
