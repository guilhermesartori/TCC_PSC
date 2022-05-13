package br.ufsc.labsec.openpsc.entity;

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

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeyPair {

  @Id
  @SequenceGenerator(name = "keypair_sequence", sequenceName = "keypair_sequence",
      allocationSize = 1)
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "keypair_sequence")
  private Long id;
  @Column(nullable = false, columnDefinition = "text")
  private String publicKey;
  @Column(nullable = false, columnDefinition = "text")
  private String privateKey;
  @Column(nullable = false)
  private String keyAlgorithm;
  @Column(nullable = false)
  private String keyParameter;
  @Column(nullable = false, unique = true)
  private String uniqueIdentifier;
  @Column(nullable = false)
  private String keyName;
  @PrimaryKeyJoinColumn
  @ManyToOne(optional = false, fetch = FetchType.LAZY)
  private AppUser owner;

  /**
   * @param publicKey
   * @param privateKey
   * @param keyAlgorithm
   * @param uniqueIdentifier
   * @param keyName
   * @param owner
   */
  public KeyPair(String publicKey, String privateKey, String keyAlgorithm, String keyParameter,
      String uniqueIdentifier, String keyName, AppUser owner) {
    super();
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.keyAlgorithm = keyAlgorithm;
    this.keyParameter = keyParameter;
    this.uniqueIdentifier = uniqueIdentifier;
    this.keyName = keyName;
    this.owner = owner;
  }

}
