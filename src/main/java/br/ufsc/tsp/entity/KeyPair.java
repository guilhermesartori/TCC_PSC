package br.ufsc.tsp.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.PrimaryKeyJoinColumn;
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
	@Column(nullable = false, unique = true)
	private String keyName;
	@PrimaryKeyJoinColumn
	@ManyToOne(optional = false, fetch = FetchType.LAZY)
	private AppUser owner;

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
	 * @param keyName
	 * @param owner
	 */
	public KeyPair(String publicKey, String privateKey, String keyAlgorithm, String uniqueIdentifier, String keyName,
			AppUser owner) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.keyAlgorithm = keyAlgorithm;
		this.uniqueIdentifier = uniqueIdentifier;
		this.keyName = keyName;
		this.owner = owner;
	}

	/**
	 * @return the publicKey
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * @return the owner
	 */
	public AppUser getOwner() {
		return owner;
	}

	/**
	 * @return the privateKey
	 */
	public String getPrivateKey() {
		return privateKey;
	}

	/**
	 * @return the keyAlgorithm
	 */
	public String getKeyAlgorithm() {
		return keyAlgorithm;
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
