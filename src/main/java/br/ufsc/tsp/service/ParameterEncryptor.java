package br.ufsc.tsp.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.stereotype.Service;

@Service
public class ParameterEncryptor {

	private static final Provider PROVIDER = new BouncyCastleProvider();
	private static final String ACCESS_KEY_ALGORITHM = "AES";
	private static final String CIPHER_TRANSFORMATION = "AES/ECB/PKCS5Padding";

	private final Cipher cipher;
	private SecretKey secretKey;

	public ParameterEncryptor() {
		try {
			this.cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, PROVIDER);
			secretKey = new SecretKeySpec(SystemKey.getKey(), SystemKey.SYSTEM_KEY_ALGORITHM);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(String dataToEncrypt, String encryptedAccessKey) {
		try {
			var accessKeySpec = encryptedAccessKeyToSecretKeySpec(encryptedAccessKey);
			cipher.init(Cipher.ENCRYPT_MODE, accessKeySpec);
			var encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
			var base64EncodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
			return base64EncodedEncryptedData;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String base64EncodedEncryptedData, String encryptedAccessKey) {
		try {
			var accessKeySpec = encryptedAccessKeyToSecretKeySpec(encryptedAccessKey);
			cipher.init(Cipher.DECRYPT_MODE, accessKeySpec);
			var encryptedData = Base64.getDecoder().decode(base64EncodedEncryptedData);
			var decryptedDataBytes = cipher.doFinal(encryptedData);
			var decryptedString = new String(decryptedDataBytes);
			return decryptedString;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	private SecretKeySpec encryptedAccessKeyToSecretKeySpec(String encryptedAccessKey) {
		var accessKey = decryptKey(encryptedAccessKey);
		var adjustedAccessKey = adjustKeySize(accessKey);
		var accessKeySpec = new SecretKeySpec(adjustedAccessKey, ACCESS_KEY_ALGORITHM);
		return accessKeySpec;
	}

	private byte[] adjustKeySize(String decryptedKey) {
		var bytes = decryptedKey.getBytes();
		byte[] newKey;
		if (bytes.length < 16)
			newKey = new byte[16];
		else if (bytes.length < 24)
			newKey = new byte[24];
		else
			newKey = new byte[32];
		Arrays.fill(newKey, Byte.valueOf("0"));
		System.arraycopy(bytes, 0, newKey, 0, bytes.length);
		return newKey;
	}

	public String encryptKey(String key) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
			var encryptedBytes = cipher.doFinal(key.getBytes());
			var base64Encryption = Base64.getEncoder().encodeToString(encryptedBytes);
			return base64Encryption;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	private String decryptKey(String encryptedKey) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
			var encryptedBytes = Base64.getDecoder().decode(encryptedKey);
			var decryptedBytes = cipher.doFinal(encryptedBytes);
			var decryptedKey = new String(decryptedBytes);
			return decryptedKey;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public Map<String, String> decryptKnetParameters(Map<String, String> encryptedParameters, String accessKey) {
		var decryptedParameters = new HashMap<String, String>();
		for (var entry : encryptedParameters.entrySet()) {
			var decryptedPramater = decrypt(entry.getValue(), accessKey);
			decryptedParameters.put(entry.getKey(), decryptedPramater);
		}
		return decryptedParameters;
	}

	public Map<String, String> encryptKnetParameters(Map<String, String> parameters, String accessKey) {
		var encryptedParameters = new HashMap<String, String>();
		for (var entry : parameters.entrySet()) {
			var encryptedPramater = encrypt(entry.getValue(), accessKey);
			encryptedParameters.put(entry.getKey(), encryptedPramater);
		}
		return encryptedParameters;
	}

}
