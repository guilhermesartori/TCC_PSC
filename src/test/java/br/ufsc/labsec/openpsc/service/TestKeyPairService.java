package br.ufsc.labsec.openpsc.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import br.ufsc.labsec.openpsc.entity.enums.Authority;
import br.ufsc.labsec.openpsc.repository.KeyPairRepository;
import br.ufsc.labsec.openpsc.service.exception.AppUserServiceException;
import br.ufsc.labsec.openpsc.service.exception.KNetCommunicationServiceException;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException;
import br.ufsc.labsec.openpsc.service.exception.SystemServiceException;
import br.ufsc.labsec.valueobject.crypto.keys.KeyManagerException;
import br.ufsc.labsec.valueobject.exception.KNetException;

@SpringBootTest
public class TestKeyPairService {

  private static final String USER_USERNAME = "test";
  private static final String USER_PASSWORD = "test";
  private static final String KEY_NAME = "test_key_name";

  @Autowired
  private KeyPairService keyPairService;

  @Autowired
  private AppUserService appUserService;

  @Autowired
  private ParameterEncryptor parameterEncryptor;

  @Autowired
  private KeyPairRepository keyPairRepository;

  @Autowired
  private KNetCommunicationService kNetCommunicationService;

  @Autowired
  private SystemConfigurationService systemConfigurationService;

  private String accessKey;

  @BeforeEach
  public void runBeforeEach() throws SystemServiceException, AppUserServiceException {
    final var authorities = new ArrayList<Authority>();
    authorities.add(Authority.USER);
    appUserService.registerNewUser(USER_USERNAME, USER_PASSWORD);
    accessKey = parameterEncryptor.encryptKey(USER_PASSWORD);
    final var parameters = new HashMap<String, String>();
    parameters.put("ADDRESS_CONN", "192.168.66.20");
    parameters.put("PORT_CONN", "60055");
    parameters.put("USERNAME", "test_user");
    parameters.put("PW", "2m;z#MkD-tcc-guilherme");
    parameters.put("MAX_CONNECTIONS", "1");
    parameters.put("TLV_PORT", "60055");
    systemConfigurationService.setKnetConfiguration(parameters, accessKey);
  }

  @AfterEach
  public void runAfterEach() throws AppUserServiceException {
    appUserService.deleteUserByUsername(USER_USERNAME);
  }

  @Test
  public void createKeyPair_RSA_2048()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";

    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertEquals(keyPair.getKeyAlgorithm(), algorithm);
    assertEquals(keyPair.getOwner().getUsername(), USER_USERNAME);
    assertNotNull(keyPair.getPrivateKey());
    assertNotNull(keyPair.getPublicKey());
    assertNotNull(keyPair.getUniqueIdentifier());
    assertNotNull(keyPair.getId());
  }

  @Test
  public void createKeyPair_RSA_2048_duplicateKeyPair()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

      keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());
    });

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());
  }

  @Test
  public void createKeyPair_RSA_2048_noSuchAlgorithm()
      throws KeyPairServiceException, KNetCommunicationServiceException {
    final var algorithm = "DASPDAPJI";
    final var parameter = "2048";

    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);
    });
  }

  @Test
  public void sign_RSA_2048_SHA256() throws KeyPairServiceException, InvalidKeyException,
      NoSuchAlgorithmException, InvalidKeySpecException, SignatureException,
      KNetCommunicationServiceException, KNetException, KeyManagerException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var hashingAlgorithm = "SHA256";
    final var dataToSign = "test".getBytes();
    final var base64EncodedDataToSign = Base64.getEncoder().encodeToString(dataToSign);
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);
    final var publicKey =
        kNetCommunicationService.getPublicKey(keyPair.getPublicKey(), algorithm, parameter);
    final var signature = Signature.getInstance("SHA256WithRSA", new BouncyCastleProvider());
    signature.initVerify(publicKey);
    signature.update(dataToSign);

    final var signedData = keyPairService.sign(USER_USERNAME, accessKey, base64EncodedDataToSign,
        keyPair.getUniqueIdentifier(), hashingAlgorithm);

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertTrue(signature.verify(Base64.getDecoder().decode(signedData)));
  }

  @Test
  public void sign_keyDoesntExist()
      throws KeyPairServiceException, InvalidKeyException, NoSuchAlgorithmException,
      InvalidKeySpecException, SignatureException, KNetCommunicationServiceException {
    final var hashingAlgorithm = "SHA256";
    final var dataToSign = "test".getBytes();
    final var base64EncodedDataToSign = Base64.getEncoder().encodeToString(dataToSign);
    final var uniqueIdentifier = "test";

    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.sign(USER_USERNAME, accessKey, base64EncodedDataToSign, uniqueIdentifier,
          hashingAlgorithm);
    });
  }

  @Test
  public void deleteKeyPair_RSA_2048()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertFalse(keyPairRepository.existsKeyPairByUniqueIdentifier(keyPair.getUniqueIdentifier()));

  }

  @Test
  public void deleteKeyPair_keyDoesntExist()
      throws KeyPairServiceException, KNetCommunicationServiceException {
    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.deleteKeyPair(USER_USERNAME, accessKey, "test");
    });

  }

  @Test
  public void getKeyPairs()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);
    final var keyPair2 = keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm,
        parameter, KEY_NAME + "2");

    final var keyPairList = keyPairService.getKeyPairs(USER_USERNAME);

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());
    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair2.getUniqueIdentifier());

    assertEquals(2, keyPairList.size());
    assertEquals(keyPair.getId(), keyPairList.get(0).getId());
    assertEquals(keyPair2.getId(), keyPairList.get(1).getId());
  }

  @Test
  public void getKeyPair()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    final var gotKeyPair = keyPairService.getKeyPair(USER_USERNAME, keyPair.getUniqueIdentifier());

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertEquals(keyPair.getId(), gotKeyPair.getId());
  }

  @Test
  public void getKeyPair_keyDoesntExist()
      throws KeyPairServiceException, KNetCommunicationServiceException {
    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.getKeyPair(USER_USERNAME, "test");
    });
  }

  @Test
  public void getKeyPairByKeyName()
      throws KeyPairServiceException, KNetCommunicationServiceException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    final var gotKeyPair = keyPairService.getKeyPairByKeyName(USER_USERNAME, keyPair.getKeyName());

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertEquals(keyPair.getId(), gotKeyPair.getId());
  }

  @Test
  public void getKeyPairByKeyName_keyDoesntExist()
      throws KeyPairServiceException, KNetCommunicationServiceException {
    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.getKeyPairByKeyName(USER_USERNAME, "test");
    });
  }

  @Test
  public void getPublicKey() throws KeyPairServiceException, KNetCommunicationServiceException,
      KeyManagerException, KNetException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);

    final var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(), algorithm, parameter);

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertNotNull(publicKey);
    assertFalse(publicKey.isBlank());
  }

  @Test
  public void getPublicKey_keyDoesntExist()
      throws KeyPairServiceException, KNetException, KNetCommunicationServiceException {
    final var algorithm = "RSA";
    final var parameter = "2048";

    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.getPublicKey("test", algorithm, parameter);
    });

  }

  @Test
  public void verifySignature() throws KeyPairServiceException, KNetException,
      KNetCommunicationServiceException, InvalidKeyException, NoSuchAlgorithmException,
      InvalidKeySpecException, SignatureException, KeyManagerException {
    final var algorithm = "RSA";
    final var parameter = "2048";
    final var hashingAlgorithm = "SHA256";
    final var dataToSign = "test".getBytes();
    final var base64EncodedDataToSign = Base64.getEncoder().encodeToString(dataToSign);
    final var keyPair =
        keyPairService.createKeyPair(USER_USERNAME, accessKey, algorithm, parameter, KEY_NAME);
    final var signedData = keyPairService.sign(USER_USERNAME, accessKey, base64EncodedDataToSign,
        keyPair.getUniqueIdentifier(), hashingAlgorithm);

    final var valid = keyPairService.verifySignature(keyPair.getUniqueIdentifier(),
        base64EncodedDataToSign, signedData, "SHA256WithRSA");

    keyPairService.deleteKeyPair(USER_USERNAME, accessKey, keyPair.getUniqueIdentifier());

    assertTrue(valid);
  }

  @Test
  public void verifySignature_keyDoesntExist()
      throws KeyPairServiceException, KNetException, KNetCommunicationServiceException {
    final var dataToSign = "test".getBytes();
    final var base64EncodedDataToSign = Base64.getEncoder().encodeToString(dataToSign);
    final var uniqueIdentifier = "test";
    final var signedData = "test";

    assertThrows(KeyPairServiceException.class, () -> {
      keyPairService.verifySignature(uniqueIdentifier, base64EncodedDataToSign, signedData,
          "SHA256WithRSA");
    });

  }

}
