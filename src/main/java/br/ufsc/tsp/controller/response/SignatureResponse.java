package br.ufsc.tsp.controller.response;

public class SignatureResponse {

	private String base64Signature;

	/**
	 * @param base64Signature
	 */
	public SignatureResponse(String base64Signature) {
		super();
		this.base64Signature = base64Signature;
	}

	/**
	 * @return the base64Signature
	 */
	public String getBase64Signature() {
		return base64Signature;
	}

}
