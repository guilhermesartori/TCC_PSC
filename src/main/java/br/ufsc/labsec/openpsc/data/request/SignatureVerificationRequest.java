package br.ufsc.labsec.openpsc.data.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignatureVerificationRequest {

  private String base64EncodedData;
  private String base64EncodedSignature;
  private String signatureAlgorithm;

}
