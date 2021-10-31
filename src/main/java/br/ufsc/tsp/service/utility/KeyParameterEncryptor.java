package br.ufsc.tsp.service.utility;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyParameterEncryptor {

	private static final Provider PROVIDER = new BouncyCastleProvider();

	private SecretKeySpec secretKey;
	private Cipher cipher;

	public KeyParameterEncryptor(SecretKeySpec secretKey) {
		this.secretKey = secretKey;
		try {
			this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", PROVIDER);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(PrivateKey privateKey) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			var encryptedBytes = cipher.doFinal(privateKey.getEncoded());
			var base64Encryption = Base64.getEncoder().encodeToString(encryptedBytes);
			return base64Encryption;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public PrivateKey decrypt(String base64Encryption, String keyAlgorithm) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			var encryptedBytes = Base64.getDecoder().decode(base64Encryption);
			var encodedKey = cipher.doFinal(encryptedBytes);
			var privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
			var keyFactory = KeyFactory.getInstance(keyAlgorithm, PROVIDER);
			var privateKey = keyFactory.generatePrivate(privateKeySpec);
			return privateKey;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
