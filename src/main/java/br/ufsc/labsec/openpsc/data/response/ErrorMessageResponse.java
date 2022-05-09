package br.ufsc.labsec.openpsc.data.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(name = "ErrorMessageResponse")
public class ErrorMessageResponse {

	public static final String DEFAULT_ERROR = "Internal error.";
	
	private String error = DEFAULT_ERROR;

}
