package br.ufsc.tsp.controller.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignatureResponse {

	private String base64EncodedSignature;
	private String keyPairUniqueIdentifier;
	private String base64EncodedPublicKey;


}
