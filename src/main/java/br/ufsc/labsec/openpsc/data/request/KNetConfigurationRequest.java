package br.ufsc.labsec.openpsc.data.request;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class KNetConfigurationRequest {

  private Map<String, String> parameters;

}
