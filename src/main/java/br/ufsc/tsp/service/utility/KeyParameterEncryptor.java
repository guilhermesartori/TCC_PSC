package br.ufsc.tsp.service.utility;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.springframework.stereotype.Service;

@Service
public class KeyParameterEncryptor {

	private static final Provider PROVIDER = new BouncyCastleProvider();

	private Cipher cipher;

	public KeyParameterEncryptor() {
		try {
			this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", PROVIDER);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(String parameter, String encryptedKey) {
		try {
			var decryptedKey = decryptKey(encryptedKey);
			var key = adjustKeySize(decryptedKey);
			var secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			var encryptedBytes = cipher.doFinal(parameter.getBytes());
			var base64Encryption = Base64.getEncoder().encodeToString(encryptedBytes);
			return base64Encryption;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
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
		// TODO Auto-generated method stub
		return key;
	}

	private String decryptKey(String encryptedKey) {
		// TODO Auto-generated method stub
		return encryptedKey;
	}

	public String decrypt(String base64Encoding, String encryptedKey) {
		try {
			var decryptedKey = decryptKey(encryptedKey);
			var key = adjustKeySize(decryptedKey);
			var secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			var encryptedBytes = Base64.getDecoder().decode(base64Encoding);
			var decryptedBytes = cipher.doFinal(encryptedBytes);
			var decryptedString = new String(decryptedBytes);
			return decryptedString;
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

}
