package br.ufsc.tsp.controller.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureRequest {

	private String hashingAlgorithm;
	private String base64EncodedData;

}
