package br.ufsc.labsec.openpsc.data.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KeyPairGenerationRequest {

	private String keyAlgorithm;
	private String keyParameter;
	private String keyName;

}
