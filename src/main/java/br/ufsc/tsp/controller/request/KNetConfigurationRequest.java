package br.ufsc.tsp.controller.request;

import java.util.Map;

public class KNetConfigurationRequest {

	private Map<String, String> parameters;

	/**
	 * 
	 */
	public KNetConfigurationRequest() {
		super();
	}

	/**
	 * @param parameters
	 */
	public KNetConfigurationRequest(Map<String, String> parameters) {
		super();
		this.parameters = parameters;
	}

	/**
	 * @return the parameters
	 */
	public Map<String, String> getParameters() {
		return parameters;
	}

	/**
	 * @param parameters the parameters to set
	 */
	public void setParameters(Map<String, String> parameters) {
		this.parameters = parameters;
	}

}
