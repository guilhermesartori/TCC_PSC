package br.ufsc.tsp.controller.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KeyResponse {

	private String keyPairUniqueIdentifier;
	private String keyAlgorithm;
	private String publicKey;
	
}
