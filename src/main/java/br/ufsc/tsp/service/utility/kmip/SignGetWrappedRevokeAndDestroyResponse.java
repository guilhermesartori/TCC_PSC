package br.ufsc.tsp.service.utility.kmip;

public class SignGetWrappedRevokeAndDestroyResponse {

	private byte[] signature;
	private byte[] redBlobWrappedKey;
	private byte[] wrappedKey;
	private String[] revocationResults;
	private String iv;

	public SignGetWrappedRevokeAndDestroyResponse() {
	}

	public SignGetWrappedRevokeAndDestroyResponse(byte[] signature, byte[] wrappedKey, String[] revocationResults) {
		super();
		this.signature = signature;
		this.redBlobWrappedKey = wrappedKey;
		this.revocationResults = revocationResults;
	}

	public byte[] getSignature() {
		return signature;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public byte[] getRedblobWrappedKey() {
		return redBlobWrappedKey;
	}

	public void setRedblobWrappedKey(byte[] wrappedKey) {
		this.redBlobWrappedKey = wrappedKey;
	}

	public String[] getRevocationResults() {
		return revocationResults;
	}

	public void setRevocationResults(String[] revocationResults) {
		this.revocationResults = revocationResults;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	public byte[] getWrappedKey() {
		return wrappedKey;
	}

	public void setWrappedKey(byte[] wrappedKey) {
		this.wrappedKey = wrappedKey;
	}

}
