package br.ufsc.tsp.controller.response;

public class SignatureResponse {

	private String base64Signature;

	/**
	 * 
	 */
	public SignatureResponse() {
		super();
	}

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

	/**
	 * @param base64Signature the base64Signature to set
	 */
	public void setBase64Signature(String base64Signature) {
		this.base64Signature = base64Signature;
	}

}
