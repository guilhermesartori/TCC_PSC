package br.ufsc.tsp.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureResponse {

	private String base64EncodedSignature;
	private String keyPairUniqueIdentifier;
	private String base64EncodedPublicKey;

}
