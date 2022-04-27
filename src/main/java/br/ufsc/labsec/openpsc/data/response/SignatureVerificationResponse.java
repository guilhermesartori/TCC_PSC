package br.ufsc.labsec.openpsc.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureVerificationResponse {

	private boolean validSignature;

}
