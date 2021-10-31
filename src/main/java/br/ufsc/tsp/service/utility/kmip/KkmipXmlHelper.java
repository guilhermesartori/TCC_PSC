package br.ufsc.tsp.service.utility.kmip;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.Objects;

import com.kryptus.security.kmip.model.field.ActivationDate;
import com.kryptus.security.kmip.model.field.AttributeName;
import com.kryptus.security.kmip.model.field.BlockCipherMode;
import com.kryptus.security.kmip.model.field.CredentialType;
import com.kryptus.security.kmip.model.field.CryptographicAlgorithm;
import com.kryptus.security.kmip.model.field.CryptographicLength;
import com.kryptus.security.kmip.model.field.CryptographicUsageMask;
import com.kryptus.security.kmip.model.field.Data;
import com.kryptus.security.kmip.model.field.DigestedData;
import com.kryptus.security.kmip.model.field.DigitalSignatureAlgorithm;
import com.kryptus.security.kmip.model.field.HashingAlgorithm;
import com.kryptus.security.kmip.model.field.IVCounterNonce;
import com.kryptus.security.kmip.model.field.KeyFormatType;
import com.kryptus.security.kmip.model.field.KeyValueField;
import com.kryptus.security.kmip.model.field.NameType;
import com.kryptus.security.kmip.model.field.NameValue;
import com.kryptus.security.kmip.model.field.ObjectType;
import com.kryptus.security.kmip.model.field.PaddingMethod;
import com.kryptus.security.kmip.model.field.Password;
import com.kryptus.security.kmip.model.field.ProtocolVersionMajor;
import com.kryptus.security.kmip.model.field.ProtocolVersionMinor;
import com.kryptus.security.kmip.model.field.RecommendedCurve;
import com.kryptus.security.kmip.model.field.RevocationMessage;
import com.kryptus.security.kmip.model.field.RevocationReasonCode;
import com.kryptus.security.kmip.model.field.UniqueIdentifier;
import com.kryptus.security.kmip.model.field.Username;
import com.kryptus.security.kmip.model.field.WrappingMethod;
import com.kryptus.security.kmip.model.structure.Attribute;
import com.kryptus.security.kmip.model.structure.Authentication;
import com.kryptus.security.kmip.model.structure.CommonTemplateAttribute;
import com.kryptus.security.kmip.model.structure.Credential;
import com.kryptus.security.kmip.model.structure.EncryptionKeyInformation;
import com.kryptus.security.kmip.model.structure.KeyBlock;
import com.kryptus.security.kmip.model.structure.KeyWrappingData;
import com.kryptus.security.kmip.model.structure.KeyWrappingSpecification;
import com.kryptus.security.kmip.model.structure.PasswordCredential;
import com.kryptus.security.kmip.model.structure.PrivateKeyTemplateAttribute;
import com.kryptus.security.kmip.model.structure.ProtocolVersion;
import com.kryptus.security.kmip.model.structure.PublicKeyTemplateAttribute;
import com.kryptus.security.kmip.model.structure.RequestHeader;
import com.kryptus.security.kmip.model.structure.TemplateAttribute;
import com.kryptus.security.kmip.model.structure.attributevalue.CryptographicDomainParameters;
import com.kryptus.security.kmip.model.structure.attributevalue.CryptographicParameters;
import com.kryptus.security.kmip.model.structure.attributevalue.Name;
import com.kryptus.security.kmip.model.structure.attributevalue.RevocationReason;
import com.kryptus.security.kmip.model.structure.managedobject.PrivateKey;
import com.kryptus.security.kmip.model.structure.requestpayload.ActivateRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.CreateKeyPairRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.DestroyRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.GetRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.RegisterRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.RevokeRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.SignRequestPayload;

import br.ufsc.tsp.exception.NoSuchCurveException;

public final class KkmipXmlHelper {

	public static RequestHeader getHeader(String username, String password) {
		RequestHeader requestHeader = new RequestHeader();
		requestHeader.protocolVersion = new ProtocolVersion();
		requestHeader.protocolVersion.protocolVersionMajor = new ProtocolVersionMajor(1);
		requestHeader.protocolVersion.protocolVersionMinor = new ProtocolVersionMinor(4);
		// TODO verificar se o usuário está bem configurado. Se não estiver, verificar
		// se o keystore está bem configurado
		if (username != null) {
			if (!username.isEmpty() && !password.isEmpty()) {
				requestHeader.authentication = new Authentication();
				requestHeader.authentication.credentials = new Credential[1];
				requestHeader.authentication.credentials[0] = getCredential(username, password);
			}
		}

		return requestHeader;
	}

	private static Credential getCredential(String username, String password) {
		Credential credential = new Credential();
		credential.credentialType = new CredentialType(CredentialType.Values.UsernameAndPassword);
		credential.credentialValue = new PasswordCredential(new Username(username), new Password(password));
		return credential;
	}

	public static CreateKeyPairRequestPayload generateKeyPair(String algorithm, String param, String publicKeyName,
			String privateKeyName) throws NoSuchCurveException {

		algorithm = formatKmipAlgorithm(algorithm);
		param = formatKmipParameter(param);

		CreateKeyPairRequestPayload requestPayload = new CreateKeyPairRequestPayload();

		// Fill the Common Template
		requestPayload.commonTemplateAttribute = new CommonTemplateAttribute();
		requestPayload.commonTemplateAttribute.attributes = new Attribute[3];
		requestPayload.commonTemplateAttribute.attributes[0] = new Attribute();
		requestPayload.commonTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.CryptographicAlgorithm);
		requestPayload.commonTemplateAttribute.attributes[0].attributeValue = new CryptographicAlgorithm(
				CryptographicAlgorithm.Values.valueOf(algorithm));
		requestPayload.commonTemplateAttribute.attributes[1] = new Attribute();
		switch (algorithm) {
		case "RSA":
			requestPayload.commonTemplateAttribute.attributes[1].attributeName = new AttributeName(
					AttributeName.Values.CryptographicLength);
			requestPayload.commonTemplateAttribute.attributes[1].attributeValue = new CryptographicLength(
					Integer.parseInt(param));
			break;
		case "ECDSA":
			try {
				RecommendedCurve.Values recommendedCurveValue = RecommendedCurve.Values.valueOf(param);
				requestPayload.commonTemplateAttribute.attributes[1].attributeName = new AttributeName(
						AttributeName.Values.CryptographicDomainParameters);
				CryptographicDomainParameters cryptographicDomainParameters = new CryptographicDomainParameters();
				cryptographicDomainParameters.recommendedCurve = new RecommendedCurve(recommendedCurveValue);
				requestPayload.commonTemplateAttribute.attributes[1].attributeValue = cryptographicDomainParameters;
			} catch (IllegalArgumentException e) {
				throw new NoSuchCurveException(param);
			}

			break;
		case "EdDSA":
			requestPayload.commonTemplateAttribute.attributes[1].attributeName = new AttributeName(
					AttributeName.Values.CryptographicDomainParameters);
			CryptographicDomainParameters cryptographicDomainParameters = new CryptographicDomainParameters();
			cryptographicDomainParameters.recommendedCurve = new RecommendedCurve(
					RecommendedCurve.Values.valueOf(param));
			requestPayload.commonTemplateAttribute.attributes[1].attributeValue = cryptographicDomainParameters;
			break;
		default:
			new NoSuchAlgorithmException(algorithm);
			break;
		}
		final Calendar cal = Calendar.getInstance();
		cal.add(Calendar.DATE, -1);

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.getDefault());
		requestPayload.commonTemplateAttribute.attributes[2] = new Attribute();
		requestPayload.commonTemplateAttribute.attributes[2].attributeName = new AttributeName(
				AttributeName.Values.ActivationDate);
		requestPayload.commonTemplateAttribute.attributes[2].attributeValue = new ActivationDate(
				dateFormat.format(cal.getTime()));

		// Fill the Private Key Template
		requestPayload.privateKeyTemplateAttribute = new PrivateKeyTemplateAttribute();
		requestPayload.privateKeyTemplateAttribute.attributes = new Attribute[2];
		requestPayload.privateKeyTemplateAttribute.attributes[0] = new Attribute();
		requestPayload.privateKeyTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.Name);
		requestPayload.privateKeyTemplateAttribute.attributes[0].attributeValue = new Name(
				new NameValue(privateKeyName), new NameType(NameType.Values.UninterpretedTextString));
		requestPayload.privateKeyTemplateAttribute.attributes[1] = new Attribute();
		requestPayload.privateKeyTemplateAttribute.attributes[1].attributeName = new AttributeName(
				AttributeName.Values.CryptographicUsageMask);
		requestPayload.privateKeyTemplateAttribute.attributes[1].attributeValue = new CryptographicUsageMask(
				CryptographicUsageMask.Values.Sign.value() | CryptographicUsageMask.Values.UnwrapKey.value());

		// Fill the Public Key Template
		requestPayload.publicKeyTemplateAttribute = new PublicKeyTemplateAttribute();
		requestPayload.publicKeyTemplateAttribute.attributes = new Attribute[2];
		requestPayload.publicKeyTemplateAttribute.attributes[0] = new Attribute();
		requestPayload.publicKeyTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.Name);
		requestPayload.publicKeyTemplateAttribute.attributes[0].attributeValue = new Name(new NameValue(publicKeyName),
				new NameType(NameType.Values.UninterpretedTextString));
		requestPayload.publicKeyTemplateAttribute.attributes[1] = new Attribute();
		requestPayload.publicKeyTemplateAttribute.attributes[1].attributeName = new AttributeName(
				AttributeName.Values.CryptographicUsageMask);
		requestPayload.publicKeyTemplateAttribute.attributes[1].attributeValue = new CryptographicUsageMask(
				CryptographicUsageMask.Values.Verify.value() | CryptographicUsageMask.Values.ContentCommitment.value()
						| CryptographicUsageMask.Values.WrapKey.value());
		return requestPayload;
	}

	public static GetRequestPayload getPublicKey(String keyAlgorithm, String uniqueIdentifier)
			throws InvalidKeySpecException {

		GetRequestPayload requestPayload = new GetRequestPayload();
		if (keyAlgorithm.equals("RSA")) {
			requestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentRSAPublicKey);
		} else if (keyAlgorithm.equals("ECDSA") || keyAlgorithm.equals("EDDSA")) {
			requestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentECPublicKey);
		} else {
			throw new InvalidKeySpecException("Unsupported key type");
		}

		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);

		return requestPayload;
	}

	public static GetRequestPayload getPrivateKey(String keyAlgorithm, String uniqueIdentifier)
			throws InvalidKeySpecException {

		GetRequestPayload requestPayload = new GetRequestPayload();
		if (keyAlgorithm.equals("RSA")) {
			requestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentRSAPrivateKey);
		} else if (keyAlgorithm.equals("ECDSA") || keyAlgorithm.equals("EDDSA")) {
			requestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentECPrivateKey);
		} else {
			throw new InvalidKeySpecException("Unsupported key type");
		}

		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);

		return requestPayload;
	}

	public static GetRequestPayload getWrappedKeyPayload(String uniqueIdentifier, String wrappingKeyUniqueIdentifier) {
		GetRequestPayload requestPayload = new GetRequestPayload();

		requestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.PKCS_8);
		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);

		CryptographicParameters cryptographicParameters = new CryptographicParameters();
		cryptographicParameters.blockCipherMode = new BlockCipherMode(BlockCipherMode.Values.NISTKeyWrap);

		EncryptionKeyInformation encryptionKeyInformation = new EncryptionKeyInformation();
		encryptionKeyInformation.uniqueIdentifier = new UniqueIdentifier(wrappingKeyUniqueIdentifier);

		KeyWrappingSpecification keyWrappingSpecification = new KeyWrappingSpecification();
		keyWrappingSpecification.wrappingMethod = new WrappingMethod(WrappingMethod.Values.Encrypt);
		encryptionKeyInformation.cryptographicParameters = cryptographicParameters;
		keyWrappingSpecification.encryptionKeyInformation = encryptionKeyInformation;
		keyWrappingSpecification.attributeNames = new AttributeName[1];
		keyWrappingSpecification.attributeNames[0] = new AttributeName(AttributeName.Values.CryptographicUsageMask);

		requestPayload.keyWrappingSpecification = keyWrappingSpecification;

		return requestPayload;
	}

	public static SignRequestPayload getSignRequestPayload(String uniqueIdentifier, String algorithm,
			byte[] digestedData) throws NoSuchAlgorithmException {

		SignRequestPayload requestPayload = new SignRequestPayload();
		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);
		CryptographicParameters cryptographicParameters = new CryptographicParameters();

		switch (algorithm) {
		case "RSA":
			cryptographicParameters.digitalSignatureAlgorithm = new DigitalSignatureAlgorithm(
					DigitalSignatureAlgorithm.Values.SHA_256WithRSAEncryption);
			cryptographicParameters.paddingMethod = new PaddingMethod(PaddingMethod.Values.PKCS1V1_5);
			cryptographicParameters.blockCipherMode = new BlockCipherMode(BlockCipherMode.Values.ECB);
			cryptographicParameters.hashingAlgorithm = new HashingAlgorithm(HashingAlgorithm.Values.SHA_256);
			requestPayload.cryptographicParameters = cryptographicParameters;
			requestPayload.digestedData = new DigestedData(digestedData);
			break;
		case "ECDSA":
			cryptographicParameters.digitalSignatureAlgorithm = new DigitalSignatureAlgorithm(
					DigitalSignatureAlgorithm.Values.ECDSAWithSHA256);
//			cryptographicParameters.paddingMethod = new PaddingMethod(PaddingMethod.Values.PKCS1V1_5);
//			cryptographicParameters.blockCipherMode = new BlockCipherMode(BlockCipherMode.Values.ECB);
			requestPayload.cryptographicParameters = cryptographicParameters;
			requestPayload.digestedData = new DigestedData(digestedData);
			break;
		case "Ed25519":
			cryptographicParameters.digitalSignatureAlgorithm = new DigitalSignatureAlgorithm(
					DigitalSignatureAlgorithm.Values.Ed25519);
			requestPayload.cryptographicParameters = cryptographicParameters;
			requestPayload.data = new Data(digestedData);
			break;
		case "Ed448":
			cryptographicParameters.digitalSignatureAlgorithm = new DigitalSignatureAlgorithm(
					DigitalSignatureAlgorithm.Values.Ed448);
			requestPayload.cryptographicParameters = cryptographicParameters;
			requestPayload.data = new Data(digestedData);
			break;
		default:
			throw new NoSuchAlgorithmException(algorithm);
		}

		return requestPayload;
	}

	public static GetRequestPayload getRedBlobGetPayload(String signingKeyIdentifier) {
		GetRequestPayload getRequestPayload = new GetRequestPayload(new UniqueIdentifier(signingKeyIdentifier),
				new KeyFormatType(KeyFormatType.Values.KnetPrivateKey), null, null, null);

		return getRequestPayload;
	}

	public static GetRequestPayload getAesWrappedPayload(String signingKeyIdentifier,
			String wrappingKeyUniqueIdentifier, String wrapBlockCipher, String iv) {
		GetRequestPayload aesRequestPayload = new GetRequestPayload();
		aesRequestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.PKCS_8);
		aesRequestPayload.uniqueIdentifier = new UniqueIdentifier(signingKeyIdentifier);
		KeyWrappingSpecification keyWrappingSpecification = new KeyWrappingSpecification();
		keyWrappingSpecification.wrappingMethod = new WrappingMethod(WrappingMethod.Values.Encrypt);
		EncryptionKeyInformation encryptionKeyInformation = new EncryptionKeyInformation();
		encryptionKeyInformation.uniqueIdentifier = new UniqueIdentifier(wrappingKeyUniqueIdentifier);
		CryptographicParameters wrappingCryptographicParameters = new CryptographicParameters();
		wrappingCryptographicParameters.blockCipherMode = new BlockCipherMode(wrapBlockCipher);

		if (Objects.equals(wrapBlockCipher, BlockCipherMode.Values.CBC.name())) {
			wrappingCryptographicParameters.paddingMethod = new PaddingMethod(PaddingMethod.Values.PKCS5);
			keyWrappingSpecification.ivCounterNonce = new IVCounterNonce(iv);
		}
		encryptionKeyInformation.cryptographicParameters = wrappingCryptographicParameters;
		keyWrappingSpecification.encryptionKeyInformation = encryptionKeyInformation;
		keyWrappingSpecification.attributeNames = new AttributeName[1];
		keyWrappingSpecification.attributeNames[0] = new AttributeName(AttributeName.Values.CryptographicUsageMask);

		aesRequestPayload.keyWrappingSpecification = keyWrappingSpecification;

		return aesRequestPayload;
	}

	public static RevokeRequestPayload getRevokeRequestPayload(String uniqueIdentifier, String revocationMessage) {
		RevokeRequestPayload requestPayload = new RevokeRequestPayload();
		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);
		RevocationReason revocationReason = new RevocationReason();
		revocationReason.revocationReasonCode = new RevocationReasonCode(RevocationReasonCode.Values.Unspecified);
		revocationReason.revocationMessage = new RevocationMessage(revocationMessage);
		requestPayload.revocationReason = revocationReason;

		return requestPayload;
	}

	public static RegisterRequestPayload getRegisterWrappedPrivateKeyPayload(String wrappedPrivateKey,
			String unwrappingAesKey, int keySize) {
		RegisterRequestPayload registerRequestPayload = new RegisterRequestPayload();

		//
		registerRequestPayload.objectType = new ObjectType(ObjectType.Values.PrivateKey);

		//
		// TODO name?
		registerRequestPayload.templateAttribute = new TemplateAttribute();
		Attribute attribute = new Attribute();
		attribute.attributeName = new AttributeName(AttributeName.Values.CryptographicUsageMask);
		attribute.attributeValue = new CryptographicUsageMask(CryptographicUsageMask.Values.Sign.value()
				| CryptographicUsageMask.Values.Verify.value() | CryptographicUsageMask.Values.ContentCommitment.value()
				| CryptographicUsageMask.Values.WrapKey.value());
		registerRequestPayload.templateAttribute.attributes = new Attribute[1];
		registerRequestPayload.templateAttribute.attributes[0] = attribute;

		//
		PrivateKey privateKey = new PrivateKey();
		privateKey.keyBlock = new KeyBlock();
		privateKey.keyBlock.keyFormatType = new KeyFormatType(KeyFormatType.Values.PKCS_8);
		privateKey.keyBlock.keyValue = new KeyValueField(wrappedPrivateKey);
		privateKey.keyBlock.cryptographicAlgorithm = new CryptographicAlgorithm(CryptographicAlgorithm.Values.RSA);
		privateKey.keyBlock.cryptographicLength = new CryptographicLength(keySize);
		privateKey.keyBlock.keyWrappingData = new KeyWrappingData();
		privateKey.keyBlock.keyWrappingData.wrappingMethod = new WrappingMethod(WrappingMethod.Values.Encrypt);
		privateKey.keyBlock.keyWrappingData.encryptionKeyInformation = new EncryptionKeyInformation();
		privateKey.keyBlock.keyWrappingData.encryptionKeyInformation.uniqueIdentifier = new UniqueIdentifier(
				unwrappingAesKey);
		privateKey.keyBlock.keyWrappingData.encryptionKeyInformation.cryptographicParameters = new CryptographicParameters();
		privateKey.keyBlock.keyWrappingData.encryptionKeyInformation.cryptographicParameters.blockCipherMode = new BlockCipherMode(
				BlockCipherMode.Values.NISTKeyWrap);
		registerRequestPayload.object = privateKey;

		return registerRequestPayload;
	}

	public static ActivateRequestPayload getActivateKeyRequestPayload(String uniqueIdentifier) {
		ActivateRequestPayload registerRequestPayload = new ActivateRequestPayload(
				new UniqueIdentifier(uniqueIdentifier));

		return registerRequestPayload;
	}

	public static DestroyRequestPayload getDestroyRequestPayload(String uniqueIdentifier) {
		DestroyRequestPayload requestPayload = new DestroyRequestPayload();
		requestPayload.uniqueIdentifier = new UniqueIdentifier(uniqueIdentifier);

		return requestPayload;
	}

	private static String formatKmipAlgorithm(String algorithm) {
		algorithm = algorithm.toUpperCase();
		if (algorithm.equals("EDDSA")) {
			algorithm = "EdDSA";
		}
		return algorithm;
		// TODO implementar os demais parametros que podem vir a ser utilizados
	}

	private static String formatKmipParameter(String parameter) throws NoSuchCurveException {
		parameter = parameter.toUpperCase();
		if (parameter.equals("ED25519"))
			parameter = "Ed25519";
		else if (parameter.equals("ED448"))
			parameter = "Ed448";
		return parameter;
	}

}
