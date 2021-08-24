package br.ufsc.tsp.keypair;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

@Entity
@Table
public class KeyPair {

	@Id
	@SequenceGenerator(name = "keypair_sequence", sequenceName = "keypair_sequence", allocationSize = 1)
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "keypair_sequence")
	private Long id;
	@Column(nullable = false, columnDefinition = "text")
	private String publicKey;
	@Column(nullable = false, columnDefinition = "text")
	private String privateKey;
	@Column(nullable = false)
	private String keyAlgorithm;
	@Column(nullable = false, unique = true)
	private String uniqueIdentifier;

	/**
	 * 
	 */
	public KeyPair() {
		super();
	}

	/**
	 * @param publicKey
	 * @param privateKey
	 * @param keyAlgorithm
	 * @param uniqueIdentifier
	 */
	public KeyPair(String publicKey, String privateKey, String keyAlgorithm, String uniqueIdentifier) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.keyAlgorithm = keyAlgorithm;
		this.uniqueIdentifier = uniqueIdentifier;
	}

	/**
	 * @return the publicKey
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * @param publicKey the publicKey to set
	 */
	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * @return the privateKey
	 */
	public String getPrivateKey() {
		return privateKey;
	}

	/**
	 * @param privateKey the privateKey to set
	 */
	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * @return the keyAlgorithm
	 */
	public String getKeyAlgorithm() {
		return keyAlgorithm;
	}

	/**
	 * @param keyAlgorithm the keyAlgorithm to set
	 */
	public void setKeyAlgorithm(String keyAlgorithm) {
		this.keyAlgorithm = keyAlgorithm;
	}

	/**
	 * @return the id
	 */
	public Long getId() {
		return id;
	}

	/**
	 * @return the uniqueIdentifier
	 */
	public String getUniqueIdentifier() {
		return uniqueIdentifier;
	}

}
