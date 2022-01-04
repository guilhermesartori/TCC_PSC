package br.ufsc.tsp.controller.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class KeyResponse {

	private String keyPairUniqueIdentifier;
	private String keyAlgorithm;
	private String publicKey;
	
}
