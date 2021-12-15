package br.ufsc.tsp.controller.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignatureVerificationResponse {

	private boolean validSignature;

}
