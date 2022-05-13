package br.ufsc.labsec.openpsc.data.response;

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
