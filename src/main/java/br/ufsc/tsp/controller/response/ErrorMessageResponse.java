package br.ufsc.tsp.controller.response;

public class ErrorMessageResponse {

	private String error;

	/**
	 * @param error
	 */
	public ErrorMessageResponse(String error) {
		super();
		this.error = error;
	}

	/**
	 * @return the error
	 */
	public String getError() {
		return error;
	}

}
