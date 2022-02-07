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
			final var accessKeySpec = encryptedAccessKeyToSecretKeySpec(encryptedAccessKey);
			cipher.init(Cipher.ENCRYPT_MODE, accessKeySpec);
			final var encryptedData = cipher.doFinal(dataToEncrypt.getBytes());
			final var base64EncodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
			return base64EncodedEncryptedData;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String base64EncodedEncryptedData, String encryptedAccessKey) {
		try {
			final var accessKeySpec = encryptedAccessKeyToSecretKeySpec(encryptedAccessKey);
			cipher.init(Cipher.DECRYPT_MODE, accessKeySpec);
			final var encryptedData = Base64.getDecoder().decode(base64EncodedEncryptedData);
			final var decryptedDataBytes = cipher.doFinal(encryptedData);
			final var decryptedString = new String(decryptedDataBytes);
			return decryptedString;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	private SecretKeySpec encryptedAccessKeyToSecretKeySpec(String encryptedAccessKey) {
		final var accessKey = decryptKey(encryptedAccessKey);
		final var adjustedAccessKey = adjustKeySize(accessKey);
		final var accessKeySpec = new SecretKeySpec(adjustedAccessKey, ACCESS_KEY_ALGORITHM);
		return accessKeySpec;
	}

	private byte[] adjustKeySize(String decryptedKey) {
		final var bytes = decryptedKey.getBytes();
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
			final var encryptedBytes = cipher.doFinal(key.getBytes());
			final var base64Encryption = Base64.getEncoder().encodeToString(encryptedBytes);
			return base64Encryption;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	private String decryptKey(String encryptedKey) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
			final var encryptedBytes = Base64.getDecoder().decode(encryptedKey);
			final var decryptedBytes = cipher.doFinal(encryptedBytes);
			final var decryptedKey = new String(decryptedBytes);
			return decryptedKey;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public Map<String, String> decryptKnetParameters(Map<String, String> encryptedParameters, String accessKey) {
		final var decryptedParameters = new HashMap<String, String>();
		for (final var entry : encryptedParameters.entrySet()) {
			final var decryptedPramater = decrypt(entry.getValue(), accessKey);
			decryptedParameters.put(entry.getKey(), decryptedPramater);
		}
		return decryptedParameters;
	}

	public Map<String, String> encryptKnetParameters(Map<String, String> parameters, String accessKey) {
		final var encryptedParameters = new HashMap<String, String>();
		for (final var entry : parameters.entrySet()) {
			final var encryptedPramater = encrypt(entry.getValue(), accessKey);
			encryptedParameters.put(entry.getKey(), encryptedPramater);
		}
		return encryptedParameters;
	}

}
