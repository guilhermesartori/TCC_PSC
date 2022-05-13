package br.ufsc.labsec.openpsc.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorMessageResponse {

  public static final String DEFAULT_ERROR = "Internal error.";

  private String error = DEFAULT_ERROR;

}
