package br.ufsc.labsec.openpsc.service;

import java.security.PublicKey;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.ufsc.labsec.openpsc.repository.KnetConfigurationRepository;
import br.ufsc.labsec.openpsc.service.exception.KNetCommunicationServiceException;
import br.ufsc.labsec.valueobject.crypto.KNetRequester;
import br.ufsc.labsec.valueobject.crypto.KeyIdentifierPair;
import br.ufsc.labsec.valueobject.crypto.keys.KeyManagerException;
import br.ufsc.labsec.valueobject.crypto.keys.knet.KNetKeyTranslator;
import br.ufsc.labsec.valueobject.exception.KNetException;
import br.ufsc.labsec.valueobject.kmip.KkmipClientBuilder;
import br.ufsc.labsec.valueobject.util.KeyType;

@Service
public class KNetCommunicationService {

  @Autowired
  private KnetConfigurationRepository knetConfigurationRepository;

  @Autowired
  private ParameterEncryptor parameterEncryptor;

  private KNetRequester kNetRequester = null;

  static {
    final var props = System.getProperties();
    props.setProperty("jdk.internal.httpclient.disableHostnameVerification",
        Boolean.TRUE.toString());
  }

  public KeyIdentifierPair createKeyPair(String keyAlgorithm, String keyParameter, String keyName)
      throws KNetCommunicationServiceException, KNetException {
    if (kNetRequester == null)
      throw new KNetCommunicationServiceException();
    final var keyIdentifierPair =
        kNetRequester.generateKeyPair(KeyType.build(keyAlgorithm, keyParameter), keyParameter,
            keyName + "-private", keyName + "-public");
    return keyIdentifierPair;
  }

  public byte[] sign(String privateKeyUniqueIdentifier, String algorithm, String parameter,
      byte[] data) throws KNetCommunicationServiceException, KNetException {
    if (kNetRequester == null)
      throw new KNetCommunicationServiceException();
    final var signature =
        kNetRequester.sign(privateKeyUniqueIdentifier, KeyType.build(algorithm, parameter), data);
    return signature;
  }

  public void deleteKeyPair(String privateKey, String publicKey)
      throws KNetCommunicationServiceException, KNetException {
    if (kNetRequester == null)
      throw new KNetCommunicationServiceException();
    kNetRequester.revokeAndDestroy(new String[] {privateKey, publicKey});
  }

  public PublicKey getPublicKey(String keyIdentifier, String keyAlgorithm, String keyParameter)
      throws KNetCommunicationServiceException, KeyManagerException, KNetException {
    if (kNetRequester == null)
      throw new KNetCommunicationServiceException();
    final var publicKey =
        kNetRequester.getPublicKey(keyIdentifier, KeyType.build(keyAlgorithm, keyParameter));
    return new KNetKeyTranslator().buildJavaPublicKey(publicKey,
        KeyType.build(keyAlgorithm, keyParameter));
  }

  public void setKnetConfiguration(Map<String, String> parameters) throws KNetException {
    this.kNetRequester = new KNetRequester(KkmipClientBuilder.build(null, null, parameters),
        parameters.get("USERNAME"), parameters.get("PW"));
  }

  public void loadKnetConfiguration(String accessKey)
      throws KNetCommunicationServiceException, KNetException {
    final var knetConfigurationList = knetConfigurationRepository.findAll();
    if (knetConfigurationList.size() > 0) {
      final var knetConfiguration = knetConfigurationList.get(0);
      final var encryptedParameters = knetConfiguration.getEncryptedParameters();
      final var decryptedParameters =
          this.parameterEncryptor.decryptKnetParameters(encryptedParameters, accessKey);
      setKnetConfiguration(decryptedParameters);
    } else
      throw new KNetCommunicationServiceException();
  }

  public boolean isKnetConfigurationLoaded() {
    return kNetRequester != null;
  }

  /**
   * @param kNetRequester the kNetRequester to set
   */
  public void setkNetRequester(KNetRequester kNetRequester) {
    this.kNetRequester = kNetRequester;
  }

}
