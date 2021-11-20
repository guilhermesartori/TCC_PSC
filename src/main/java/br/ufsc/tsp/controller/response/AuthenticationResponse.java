package br.ufsc.tsp.controller.response;

public class AuthenticationResponse {

	private String accessToken;

	/**
	 * 
	 */
	public AuthenticationResponse() {
		super();
	}

	/**
	 * @param accessToken
	 */
	public AuthenticationResponse(String accessToken) {
		super();
		this.accessToken = accessToken;
	}

	/**
	 * @return the accessToken
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * @param accessToken the accessToken to set
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
