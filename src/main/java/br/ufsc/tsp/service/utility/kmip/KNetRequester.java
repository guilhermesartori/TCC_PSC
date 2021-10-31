package br.ufsc.tsp.service.utility.kmip;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import com.kryptus.security.kmip.client.DefaultClient;
import com.kryptus.security.kmip.client.exception.SendRequestException;
import com.kryptus.security.kmip.model.exception.DecodeException;
import com.kryptus.security.kmip.model.exception.EncodeException;
import com.kryptus.security.kmip.model.field.AttributeName;
import com.kryptus.security.kmip.model.field.BatchCount;
import com.kryptus.security.kmip.model.field.BlockCipherMode;
import com.kryptus.security.kmip.model.field.BlockCipherMode.Values;
import com.kryptus.security.kmip.model.field.CryptographicAlgorithm;
import com.kryptus.security.kmip.model.field.CryptographicLength;
import com.kryptus.security.kmip.model.field.CryptographicUsageMask;
import com.kryptus.security.kmip.model.field.KeyFormatType;
import com.kryptus.security.kmip.model.field.KeyMaterialField;
import com.kryptus.security.kmip.model.field.KeyValueField;
import com.kryptus.security.kmip.model.field.NameType;
import com.kryptus.security.kmip.model.field.NameValue;
import com.kryptus.security.kmip.model.field.Operation;
import com.kryptus.security.kmip.model.field.ResultStatus;
import com.kryptus.security.kmip.model.field.RevocationReasonCode;
import com.kryptus.security.kmip.model.structure.Attribute;
import com.kryptus.security.kmip.model.structure.BatchItem;
import com.kryptus.security.kmip.model.structure.CommonTemplateAttribute;
import com.kryptus.security.kmip.model.structure.KeyValueStructure;
import com.kryptus.security.kmip.model.structure.PrivateKeyTemplateAttribute;
import com.kryptus.security.kmip.model.structure.PublicKeyTemplateAttribute;
import com.kryptus.security.kmip.model.structure.RequestBatchItem;
import com.kryptus.security.kmip.model.structure.RequestHeader;
import com.kryptus.security.kmip.model.structure.RequestMessage;
import com.kryptus.security.kmip.model.structure.ResponseBatchItem;
import com.kryptus.security.kmip.model.structure.ResponseMessage;
import com.kryptus.security.kmip.model.structure.attributevalue.Name;
import com.kryptus.security.kmip.model.structure.attributevalue.RevocationReason;
import com.kryptus.security.kmip.model.structure.keymaterialstructure.TransparentECPublicKey;
import com.kryptus.security.kmip.model.structure.keymaterialstructure.TransparentRSAPublicKey;
import com.kryptus.security.kmip.model.structure.managedobject.PrivateKey;
import com.kryptus.security.kmip.model.structure.managedobject.PublicKey;
import com.kryptus.security.kmip.model.structure.requestpayload.ActivateRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.CreateKeyPairRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.DestroyRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.GetRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.LocateRequestPayload;
import com.kryptus.security.kmip.model.structure.requestpayload.RevokeRequestPayload;
import com.kryptus.security.kmip.model.structure.responsepayload.ActivateResponsePayload;
import com.kryptus.security.kmip.model.structure.responsepayload.CreateKeyPairResponsePayload;
import com.kryptus.security.kmip.model.structure.responsepayload.GetResponsePayload;
import com.kryptus.security.kmip.model.structure.responsepayload.LocateResponsePayload;
import com.kryptus.security.kmip.model.structure.responsepayload.RegisterResponsePayload;
import com.kryptus.security.kmip.model.structure.responsepayload.SignResponsePayload;
import com.kryptus.security.provider.key.RecommendedCurveNames;

import br.ufsc.tsp.exception.KNetException;
import br.ufsc.tsp.exception.NoSuchCurveException;
import br.ufsc.tsp.service.utility.KeyIdentifierPair;

public final class KNetRequester {

	private final DefaultClient client;
	private final RequestHeader header;

	private static final String DEFAULT_REVOCATION_MESSAGE = "This object is gonna be destroyed";

	public KNetRequester(DefaultClient client, String username, String password) {
		this.client = client;
		this.header = KkmipXmlHelper.getHeader(username, password);
	}

	public KeyIdentifierPair generateKeyPair(String keyAlgorithm, String keyParameter, String publicKeyName,
			String privateKeyName) throws KNetException {

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];

		// Fill the batch item
		batchItem.operation = new Operation(Operation.Values.CreateKeyPair);
		try {
			batchItem.requestPayload = KkmipXmlHelper.generateKeyPair(keyAlgorithm, keyParameter, publicKeyName,
					privateKeyName);
		} catch (NoSuchCurveException e) {
			throw new KNetException("Error creating payload: " + e.getMessage(), e.getCause());
		}

		// Send the request and read the response
		ResponseMessage response = sendMessage(request, this.client);

		// Get the private and public key UID from response
		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		CreateKeyPairResponsePayload responsePayload = (CreateKeyPairResponsePayload) responseBatchItem.responsePayload;

		String privateUid = responsePayload.privateKeyUniqueIdentifier.value;
		String publicUid = responsePayload.publicKeyUniqueIdentifier.value;
		return new KeyIdentifierPair(publicUid, privateUid);
	}

	public java.security.PublicKey getPublicKey(String uniqueIdentifier, String keyAlgorithm) throws KNetException {
		keyAlgorithm = keyAlgorithm.toUpperCase();

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];
		GetRequestPayload requestPayload = null;
		try {
			requestPayload = KkmipXmlHelper.getPublicKey(keyAlgorithm, uniqueIdentifier);
		} catch (InvalidKeySpecException e) {
			throw new KNetException("Error creating payload: " + e.getMessage(), e.getCause());
		}

		batchItem.operation = new Operation(Operation.Values.Get);
		batchItem.requestPayload = requestPayload;

		ResponseMessage response = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		GetResponsePayload responsePayload = (GetResponsePayload) responseBatchItem.responsePayload;

		PublicKey publicKey = (PublicKey) responsePayload.object;
		KeyValueStructure keyValueStructure = (KeyValueStructure) publicKey.keyBlock.keyValue;

		switch (keyAlgorithm) {
		case "RSA": {
			return buildJavaRsaPublicKey(keyValueStructure);
		}
		case "ECDSA": {
			return buildJavaECPublicKey(keyValueStructure);
		}
		case "EDDSA": {
			TransparentECPublicKey keyMaterial = (TransparentECPublicKey) keyValueStructure.keyMaterial;
			String qString = keyMaterial.qString.value;
			if (keyMaterial.recommendedCurve.value.equals("Ed25519")) {
				try {
					// get w

					Ed25519PublicKeyParameters edParam = new Ed25519PublicKeyParameters(
							DatatypeConverter.parseHexBinary(qString), 0);
					SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory
							.createSubjectPublicKeyInfo(edParam);
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
					KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
					return keyFactory.generatePublic(keySpec);
				} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
					throw new KNetException("Failed to create key: " + e.getMessage(), e.getCause());
				}
			} else if (keyMaterial.recommendedCurve.value.equals("Ed448")) {
				try {
					Ed448PublicKeyParameters edParam = new Ed448PublicKeyParameters(
							DatatypeConverter.parseHexBinary(qString), 0);
					SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory
							.createSubjectPublicKeyInfo(edParam);
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
					KeyFactory keyFactory = KeyFactory.getInstance("Ed448");
					return keyFactory.generatePublic(keySpec);
				} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
					throw new KNetException("Failed to create key: " + e.getMessage(), e.getCause());
				}
			} else {
				NoSuchCurveException e = new NoSuchCurveException(keyMaterial.recommendedCurve.value);
				throw new KNetException("Error building key: " + e.getMessage(), e.getCause());
			}
		}
		default:
			InvalidKeySpecException e = new InvalidKeySpecException("Unsuported key type");
			throw new KNetException("Error building key: " + e.getMessage(), e.getCause());
		}
	}

	public byte[] getWrappedPrivateKey(String uniqueIdentifier, String wrappingKeyUniqueIdentifier)
			throws KNetException {
		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];
		batchItem.operation = new Operation(Operation.Values.Get);
		batchItem.requestPayload = KkmipXmlHelper.getWrappedKeyPayload(uniqueIdentifier, wrappingKeyUniqueIdentifier);

		ResponseMessage response = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		GetResponsePayload responsePayload = (GetResponsePayload) responseBatchItem.responsePayload;

		PrivateKey privateKey = (PrivateKey) responsePayload.object;
		KeyValueField keyValue = (KeyValueField) privateKey.keyBlock.keyValue;
		byte[] privateKeyBytes = DatatypeConverter.parseHexBinary(keyValue.value);

		return privateKeyBytes;
	}

	public byte[] sign(String uniqueIdentifier, String algorithm, byte[] digestedData) throws KNetException {
		algorithm = algorithm.toUpperCase();
		algorithm = algorithm.equals("ED448") ? "Ed448" : algorithm;
		algorithm = algorithm.equals("ED25519") ? "Ed25519" : algorithm;

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];
		batchItem.operation = new Operation(Operation.Values.Sign);
		try {
			batchItem.requestPayload = KkmipXmlHelper.getSignRequestPayload(uniqueIdentifier, algorithm, digestedData);
		} catch (NoSuchAlgorithmException e) {
			throw new KNetException("Failed to create payload: " + e.getMessage(), e.getCause());
		}

		ResponseMessage response = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		SignResponsePayload responsePayload = (SignResponsePayload) responseBatchItem.responsePayload;
		return DatatypeConverter.parseHexBinary(responsePayload.signatureData.value);
	}

	public String[] revokeAndDestroy(String[] uniqueIdentifiers) throws KNetException {
		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 2 * uniqueIdentifiers.length;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		for (int i = 0; i < uniqueIdentifiers.length; i++) {
			request.batchItems[i] = new RequestBatchItem();

			// Prepare batch item
			RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[i];
			batchItem.operation = new Operation(Operation.Values.Revoke);
			batchItem.requestPayload = KkmipXmlHelper.getRevokeRequestPayload(uniqueIdentifiers[i],
					DEFAULT_REVOCATION_MESSAGE);
		}
		for (int i = uniqueIdentifiers.length; i < request.batchItems.length; i++) {
			request.batchItems[i] = new RequestBatchItem();

			// Prepare batch item
			RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[i];
			batchItem.operation = new Operation(Operation.Values.Destroy);
			batchItem.requestPayload = KkmipXmlHelper
					.getDestroyRequestPayload(uniqueIdentifiers[i - uniqueIdentifiers.length]);
		}

		ResponseMessage response = sendMessage(request, this.client);

		String[] status = new String[numberOfBatchItems];
		for (int i = 0; i < 2 * uniqueIdentifiers.length; i++) {
			ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[i];
			status[i] = responseBatchItem.resultStatus.value;
			if (!responseBatchItem.resultStatus.value.equals("Success")) {
				status[i] = status[i] + ": " + responseBatchItem.resultMessage.value;
			}
		}
		return status;
	}

	public void revoke(String uniqueIdentifier) throws KNetException {
		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[1];
		request.batchItems[0] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];
		batchItem.operation = new Operation(Operation.Values.Revoke);
		batchItem.requestPayload = KkmipXmlHelper.getRevokeRequestPayload(uniqueIdentifier, DEFAULT_REVOCATION_MESSAGE);

		ResponseMessage response = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		if (!responseBatchItem.resultStatus.value.equals("Succesful")) {
			throw new RuntimeException("Failed to destroy object: " + responseBatchItem.resultMessage.value);
		}
	}

	/**
	 * Methods to register a wrapped private key to the HSM. Only works with RSA
	 * keys.
	 * 
	 * @param wrappedPrivateKeyAlias
	 * @param wrappedPrivateKey
	 * @param unwrappingAesKey
	 * @param keySize
	 * @return
	 * @throws EncodeException
	 * @throws DecodeException
	 * @throws SendRequestException
	 * @throws IOException
	 */
	public String registerWrappedPrivateKey(String wrappedPrivateKeyAlias, String wrappedPrivateKey, int keySize,
			String unwrappingAesKey) throws KNetException {
		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		RequestBatchItem requestBatchItem = new RequestBatchItem();

		// Fill the request batch item
		requestBatchItem.operation = new Operation(Operation.Values.Register);
		requestBatchItem.requestPayload = KkmipXmlHelper.getRegisterWrappedPrivateKeyPayload(wrappedPrivateKey,
				unwrappingAesKey, keySize);

		// Return the batch item list
		request.batchItems = new BatchItem[] { requestBatchItem };
		request.requestHeader.batchCount = new BatchCount(request.batchItems.length);

		ResponseMessage responseMessage = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) responseMessage.batchItems[0];
//		if (!(responseBatchItem.resultStatus.value.equalsIgnoreCase(ResultStatus.Values.Success.name()))) {
//			System.out.println(responseBatchItem.resultMessage.value);
//		}
		RegisterResponsePayload responsePayload = (RegisterResponsePayload) responseBatchItem.responsePayload;
		String registeredPrivateKeyUniqueIdentifier = responsePayload.uniqueIdentifier.value;

		return registeredPrivateKeyUniqueIdentifier;
	}

	/**
	 * 
	 * @param uniqueIdentifier
	 * @return
	 * @throws EncodeException
	 * @throws DecodeException
	 * @throws SendRequestException
	 * @throws IOException
	 */
	public String activateKey(String uniqueIdentifier)
			throws EncodeException, DecodeException, SendRequestException, IOException, KNetException {
		RequestMessage request = new RequestMessage();
		request.requestHeader = this.header;

		RequestBatchItem requestBatchItem = new RequestBatchItem();
		// Fill the request batch item
		requestBatchItem.operation = new Operation(Operation.Values.Activate);
		requestBatchItem.requestPayload = KkmipXmlHelper.getActivateKeyRequestPayload(uniqueIdentifier);

		// Return the batch item list
		request.batchItems = new BatchItem[] { requestBatchItem };
		request.requestHeader.batchCount = new BatchCount(request.batchItems.length);

		ResponseMessage responseMessage = this.client.sendRequest(request);
		checkMalformedResponse(responseMessage);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) responseMessage.batchItems[0];
		ActivateResponsePayload responsePayload = (ActivateResponsePayload) responseBatchItem.responsePayload;
		String activatedPrivateKeyUniqueIdentifier = responsePayload.uniqueIdentifier.value;

		return activatedPrivateKeyUniqueIdentifier;
	}

	public String[] locateObject(Map<String, String> attributeNamesAndValues) throws KNetException {
		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 1;
		request.requestHeader = this.header;
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();

		RequestBatchItem requestBatchItem = (RequestBatchItem) request.batchItems[0];
		LocateRequestPayload locateRequestPayload = new LocateRequestPayload();
		Attribute[] attributes = new Attribute[attributeNamesAndValues.size()];
		int i = 0;
		for (Map.Entry<String, String> entry : attributeNamesAndValues.entrySet()) {
			Attribute attribute = new Attribute();
			attribute.attributeName = new AttributeName(AttributeName.Values.valueOf(entry.getKey()));
			attribute.attributeValue = new Name(new NameValue(entry.getValue()),
					new NameType(NameType.Values.UninterpretedTextString));
			attributes[i] = attribute;
			i++;
		}
		locateRequestPayload.attributes = attributes;

		requestBatchItem.operation = new Operation(Operation.Values.Locate);
		requestBatchItem.requestPayload = locateRequestPayload;

		ResponseMessage responseMessage = sendMessage(request, this.client);

		ResponseBatchItem responseBatchItem = (ResponseBatchItem) responseMessage.batchItems[0];
		LocateResponsePayload responsePayload = (LocateResponsePayload) responseBatchItem.responsePayload;
		int numberOfObjectsFound = Integer.parseInt(responsePayload.locatedItems.value);
		String[] uniqueIdentifiers = new String[numberOfObjectsFound];
		for (i = 0; i < uniqueIdentifiers.length; i++) {
			uniqueIdentifiers[i] = responsePayload.uniqueIdentifiers[i].value;
		}

		return uniqueIdentifiers;
	}

	public String[] locateObject(String attributeName, String attributeValue) throws KNetException {
		HashMap<String, String> attributeNamesAndValues = new HashMap<String, String>();
		attributeNamesAndValues.put(attributeName, attributeValue);
		return this.locateObject(attributeNamesAndValues);
	}

	public GenerateAndGetResponse generateKeyPairAndGetPublicKey(String algorithm, String param, String publicKeyName,
			String privateKeyName) throws InvalidKeySpecException, NoSuchCurveException, IOException,
			NoSuchAlgorithmException, InvalidParameterSpecException, NoSuchProviderException, KNetException {
		algorithm = algorithm.toUpperCase();
		param = param.toUpperCase();
		if (algorithm.equals("EDDSA")) {
			algorithm = "EdDSA";
			if (param.equals("ED25519"))
				param = "Ed25519";
			else if (param.equals("ED448"))
				param = "Ed448";
			else
				throw new NoSuchCurveException(param);
		}

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = 2;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];
		request.batchItems[0] = new RequestBatchItem();
		request.batchItems[1] = new RequestBatchItem();

		// Prepare batch item
		RequestBatchItem batchItem = (RequestBatchItem) request.batchItems[0];
		// Fill the batch item
		batchItem.operation = new Operation(Operation.Values.CreateKeyPair);
		batchItem.requestPayload = KkmipXmlHelper.generateKeyPair(algorithm, param, publicKeyName, privateKeyName);

		// Prepare batch item
		RequestBatchItem getBatchItem = (RequestBatchItem) request.batchItems[1];
		GetRequestPayload GetRequestPayload = new GetRequestPayload();
		if (algorithm.equals("RSA")) {
			GetRequestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentRSAPublicKey);
		} else if (algorithm.equals("ECDSA") || GetRequestPayload.equals("EDDSA")) {
			GetRequestPayload.keyFormatType = new KeyFormatType(KeyFormatType.Values.TransparentECPublicKey);
		} else {
			throw new InvalidKeySpecException("Unsupported key type");
		}

		getBatchItem.operation = new Operation(Operation.Values.Get);
		getBatchItem.requestPayload = GetRequestPayload;

		// Send the request and read the response
		ResponseMessage response = sendMessage(request, this.client);

		// Get the private and public key UID from response
		ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[0];
		CreateKeyPairResponsePayload responsePayload = (CreateKeyPairResponsePayload) responseBatchItem.responsePayload;

		ResponseBatchItem GetResponseBatchItem = (ResponseBatchItem) response.batchItems[1];
		GetResponsePayload getResponsePayload = (GetResponsePayload) GetResponseBatchItem.responsePayload;

		String privateUid = responsePayload.privateKeyUniqueIdentifier.value;
		String publicUid = responsePayload.publicKeyUniqueIdentifier.value;

		GenerateAndGetResponse batchResponse = new GenerateAndGetResponse();
		batchResponse.setKeyIdentifierPair(new KeyIdentifierPair(publicUid, privateUid));

		PublicKey publicKey = (PublicKey) getResponsePayload.object;
		KeyValueStructure keyValueStructure = (KeyValueStructure) publicKey.keyBlock.keyValue;

		switch (algorithm) {
		case "RSA": {
			java.security.PublicKey javaPublicKey = buildJavaRsaPublicKey(keyValueStructure);
			batchResponse.setPublicKey(javaPublicKey);
			break;
		}
		case "ECDSA": {
			TransparentECPublicKey keyMaterial = (TransparentECPublicKey) keyValueStructure.keyMaterial;

			// get w
			String qString = keyMaterial.qString.value;
			qString = qString.substring(2);
			BigInteger x = new BigInteger(1,
					DatatypeConverter.parseHexBinary(qString.substring(0, qString.length() / 2)));
			BigInteger y = new BigInteger(1, DatatypeConverter.parseHexBinary(qString.substring(qString.length() / 2)));
			ECPoint w = new ECPoint(x, y);

			// get spec
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
			parameters.init(new ECGenParameterSpec(RecommendedCurveNames.getName(keyMaterial.recommendedCurve.value)));
			ECParameterSpec paramSpec = parameters.<ECParameterSpec>getParameterSpec(ECParameterSpec.class);

			ECPublicKeySpec publicKeyParameters = new ECPublicKeySpec(w, paramSpec);
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			java.security.PublicKey javaPublicKey = keyFactory.generatePublic(publicKeyParameters);

			batchResponse.setPublicKey(javaPublicKey);
			break;
		}
		case "EdDSA": {
			TransparentECPublicKey keyMaterial = (TransparentECPublicKey) keyValueStructure.keyMaterial;
			if (keyMaterial.recommendedCurve.value.equals("Ed25519")) {
				// get w
				String qString = keyMaterial.qString.value;

				Ed25519PublicKeyParameters edParam = new Ed25519PublicKeyParameters(
						DatatypeConverter.parseHexBinary(qString), 0);
				SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory
						.createSubjectPublicKeyInfo(edParam);
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
				KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
				batchResponse.setPublicKey(keyFactory.generatePublic(keySpec));
				;
			} else if (keyMaterial.recommendedCurve.value.equals("Ed448")) {
				String qString = keyMaterial.qString.value;

				Ed448PublicKeyParameters edParam = new Ed448PublicKeyParameters(
						DatatypeConverter.parseHexBinary(qString), 0);
				SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory
						.createSubjectPublicKeyInfo(edParam);
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
				KeyFactory keyFactory = KeyFactory.getInstance("Ed448");
				batchResponse.setPublicKey(keyFactory.generatePublic(keySpec));
				;
			} else {
				throw new NoSuchCurveException(keyMaterial.recommendedCurve.value);
			}
			break;
		}
		default:
			throw new InvalidKeySpecException("Unsupported key type");
		}

		return batchResponse;
	}

	public SignGetWrappedRevokeAndDestroyResponse signGetWrappedRevokeAndDestroy(String algorithm, byte[] digestedData,
			String signingKeyIdentifier, String wrappingKeyUniqueIdentifier, String[] keysToDestroyIdentifiers)
			throws KNetException {
		return signGetWrappedRevokeAndDestroy(algorithm, digestedData, signingKeyIdentifier,
				wrappingKeyUniqueIdentifier, keysToDestroyIdentifiers, "NISTKeyWrap", null, true);
	}

	/**
	 * Signs and destroys keys. Wrapping and redblob are optional. Passing null to
	 * wrapCipher disables the AES wrapping. Passing false to redblob disables it.
	 * 
	 * @param algorithm                   is the algorithm used
	 * @param digestedData                is the data to be signed
	 * @param signingKeyIdentifier        is the identifier of the private key
	 * @param wrappingKeyUniqueIdentifier is the identifier of the AES key used for
	 *                                    wrapping
	 * @param keysToDestroyIdentifiers    is the identifiers of the keys to be
	 *                                    destroyed
	 * @param wrapCipher                  is the wrap cipher. If null, no wrapping
	 *                                    is done
	 * @param iv                          required if the wrapping is "CBC"
	 * @param redblob                     false disables redblob get.
	 * @return batch response of size according to the operations selected.
	 * @throws KNetException
	 */
	public SignGetWrappedRevokeAndDestroyResponse signGetWrappedRevokeAndDestroy(String algorithm, byte[] digestedData,
			String signingKeyIdentifier, String wrappingKeyUniqueIdentifier, String[] keysToDestroyIdentifiers,
			String wrapCipher, String iv, boolean redblob) throws KNetException {
		int operationsCount = 1;
		operationsCount = redblob ? operationsCount + 1 : operationsCount;
		boolean aesWrap = wrapCipher != null;
		operationsCount = aesWrap ? operationsCount + 1 : operationsCount;

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = operationsCount + 2 * keysToDestroyIdentifiers.length;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];

		int currentBatch = 0;

		request.batchItems[currentBatch] = new RequestBatchItem();

		algorithm = algorithm.toUpperCase();
		algorithm = algorithm.equals("ED448") ? "Ed448" : algorithm;
		algorithm = algorithm.equals("ED25519") ? "Ed25519" : algorithm;

		// Prepare batch item
		RequestBatchItem signBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

		signBatchItem.operation = new Operation(Operation.Values.Sign);
		try {
			signBatchItem.requestPayload = KkmipXmlHelper.getSignRequestPayload(signingKeyIdentifier, algorithm,
					digestedData);
		} catch (NoSuchAlgorithmException e) {
			throw new KNetException("Error creating payload: " + e.getMessage(), e.getCause());
		}

		currentBatch += 1;

		if (redblob) {
			// Prepare batch item
			request.batchItems[currentBatch] = new RequestBatchItem();
			RequestBatchItem getBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

			getBatchItem.operation = new Operation(Operation.Values.Get);
			getBatchItem.requestPayload = KkmipXmlHelper.getRedBlobGetPayload(signingKeyIdentifier);
			currentBatch += 1;
		}

		if (aesWrap) {
			request.batchItems[currentBatch] = new RequestBatchItem();
			RequestBatchItem getAesBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

			getAesBatchItem.operation = new Operation(Operation.Values.Get);
			getAesBatchItem.requestPayload = KkmipXmlHelper.getAesWrappedPayload(signingKeyIdentifier,
					wrappingKeyUniqueIdentifier, wrapCipher, iv);
			currentBatch += 1;
		}

		for (String keysToDestroyIdentifier : keysToDestroyIdentifiers) {
			request.batchItems[currentBatch] = new RequestBatchItem();

			RequestBatchItem revokeBatchItem = (RequestBatchItem) request.batchItems[currentBatch];
			revokeBatchItem.operation = new Operation(Operation.Values.Revoke);
			revokeBatchItem.requestPayload = KkmipXmlHelper.getRevokeRequestPayload(keysToDestroyIdentifier,
					DEFAULT_REVOCATION_MESSAGE);
			currentBatch += 1;
		}
		for (String keysToDestroyIdentifier : keysToDestroyIdentifiers) {
			request.batchItems[currentBatch] = new RequestBatchItem();

			// Prepare batch item
			RequestBatchItem destroyBatchItem = (RequestBatchItem) request.batchItems[currentBatch];
			destroyBatchItem.operation = new Operation(Operation.Values.Destroy);
			destroyBatchItem.requestPayload = KkmipXmlHelper.getDestroyRequestPayload(keysToDestroyIdentifier);
			currentBatch += 1;
		}

		ResponseMessage response = sendMessage(request, this.client);

		currentBatch = 0;

		ResponseBatchItem signResponseBatchItem = (ResponseBatchItem) response.batchItems[currentBatch];
		SignResponsePayload signResponsePayload = (SignResponsePayload) signResponseBatchItem.responsePayload;
		byte[] signature = DatatypeConverter.parseHexBinary(signResponsePayload.signatureData.value);

		SignGetWrappedRevokeAndDestroyResponse batchResponse = new SignGetWrappedRevokeAndDestroyResponse();
		batchResponse.setSignature(signature);

		currentBatch += 1;
		if (redblob) {
			ResponseBatchItem redBlobResponseItem = (ResponseBatchItem) response.batchItems[currentBatch];
			GetResponsePayload redblobResponsePayload = (GetResponsePayload) redBlobResponseItem.responsePayload;
			PrivateKey redblobPrivateKey = (PrivateKey) redblobResponsePayload.object;
			KeyValueStructure redblobKeyValuestructure = (KeyValueStructure) redblobPrivateKey.keyBlock.keyValue;
			KeyMaterialField redblobKeyMaterialField = (KeyMaterialField) redblobKeyValuestructure.keyMaterial;
			byte[] redblobPrivateKeyBytes = DatatypeConverter.parseHexBinary(redblobKeyMaterialField.value);

			batchResponse.setRedblobWrappedKey(redblobPrivateKeyBytes);
			currentBatch += 1;
		}

		if (aesWrap) {
			ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[currentBatch];
			GetResponsePayload responsePayload = (GetResponsePayload) responseBatchItem.responsePayload;

			PrivateKey privateKey = (PrivateKey) responsePayload.object;

			KeyValueField keyValue = (KeyValueField) privateKey.keyBlock.keyValue;
			byte[] privateKeyBytes = DatatypeConverter.parseHexBinary(keyValue.value);

			batchResponse.setWrappedKey(privateKeyBytes);
			Values blockCipher = BlockCipherMode.Values.valueOf(wrapCipher);

			if (blockCipher == BlockCipherMode.Values.CBC) {
				batchResponse.setIv(iv);
			}
			currentBatch += 1;
		}

		String[] status = new String[2 * keysToDestroyIdentifiers.length];
		for (int i = 0; i < 2 * keysToDestroyIdentifiers.length; i++) {
			ResponseBatchItem revokeResponseBatchItem = (ResponseBatchItem) response.batchItems[currentBatch];
			status[i] = revokeResponseBatchItem.resultStatus.value;
			if (!revokeResponseBatchItem.resultStatus.value.equals("Success")) {
				status[i] = status[i] + ": " + revokeResponseBatchItem.resultMessage.value;
			}
			currentBatch += 1;
		}

		batchResponse.setRevocationResults(status);
		return batchResponse;
	}

	/**
	 * Signs and destroys keys. Wrapping and redblob are optional. Passing null to
	 * wrapCipher disables the AES wrapping. Passing false to redblob disables it.
	 * 
	 * @param algorithm                   is the algorithm used
	 * @param digestedData                is the data to be signed
	 * @param signingKeyIdentifier        is the identifier of the private key
	 * @param wrappingKeyUniqueIdentifier is the identifier of the AES key used for
	 *                                    wrapping
	 * @param keysToDestroyIdentifiers    is the identifiers of the keys to be
	 *                                    destroyed
	 * @param wrapCipher                  is the wrap cipher. If null, no wrapping
	 *                                    is done
	 * @param iv                          required if the wrapping is "CBC"
	 * @param redblob                     false disables redblob get.
	 * @return batch response of size according to the operations selected.
	 * @throws KNetException
	 */
	public SignGetWrappedRevokeAndDestroyResponse signGetWrapped(String algorithm, byte[] digestedData,
			String signingKeyIdentifier, String wrappingKeyUniqueIdentifier, String wrapCipher, String iv,
			boolean redblob) throws KNetException {
		int operationsCount = 1;
		operationsCount = redblob ? operationsCount + 1 : operationsCount;
		boolean aesWrap = wrapCipher != null;
		operationsCount = aesWrap ? operationsCount + 1 : operationsCount;

		RequestMessage request = new RequestMessage();
		int numberOfBatchItems = operationsCount;
		request.requestHeader = this.header;
		request.requestHeader.batchCount = new BatchCount(numberOfBatchItems);
		request.batchItems = new BatchItem[numberOfBatchItems];

		int currentBatch = 0;

		request.batchItems[currentBatch] = new RequestBatchItem();

		algorithm = algorithm.toUpperCase();
		algorithm = algorithm.equals("ED448") ? "Ed448" : algorithm;
		algorithm = algorithm.equals("ED25519") ? "Ed25519" : algorithm;

		// Prepare batch item
		RequestBatchItem signBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

		signBatchItem.operation = new Operation(Operation.Values.Sign);
		try {
			signBatchItem.requestPayload = KkmipXmlHelper.getSignRequestPayload(signingKeyIdentifier, algorithm,
					digestedData);
		} catch (NoSuchAlgorithmException e) {
			throw new KNetException("Error creating payload: " + e.getMessage(), e.getCause());
		}

		currentBatch += 1;

		if (redblob) {
			// Prepare batch item
			request.batchItems[currentBatch] = new RequestBatchItem();
			RequestBatchItem getBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

			getBatchItem.operation = new Operation(Operation.Values.Get);
			getBatchItem.requestPayload = KkmipXmlHelper.getRedBlobGetPayload(signingKeyIdentifier);
			currentBatch += 1;
		}

		if (aesWrap) {
			request.batchItems[currentBatch] = new RequestBatchItem();
			RequestBatchItem getAesBatchItem = (RequestBatchItem) request.batchItems[currentBatch];

			getAesBatchItem.operation = new Operation(Operation.Values.Get);
			getAesBatchItem.requestPayload = KkmipXmlHelper.getAesWrappedPayload(signingKeyIdentifier,
					wrappingKeyUniqueIdentifier, wrapCipher, iv);
			currentBatch += 1;
		}

		ResponseMessage response = sendMessage(request, this.client);

		currentBatch = 0;

		ResponseBatchItem signResponseBatchItem = (ResponseBatchItem) response.batchItems[currentBatch];
		SignResponsePayload signResponsePayload = (SignResponsePayload) signResponseBatchItem.responsePayload;
		byte[] signature = DatatypeConverter.parseHexBinary(signResponsePayload.signatureData.value);

		SignGetWrappedRevokeAndDestroyResponse batchResponse = new SignGetWrappedRevokeAndDestroyResponse();
		batchResponse.setSignature(signature);

		currentBatch += 1;
		if (redblob) {
			ResponseBatchItem redBlobResponseItem = (ResponseBatchItem) response.batchItems[currentBatch];
			GetResponsePayload redblobResponsePayload = (GetResponsePayload) redBlobResponseItem.responsePayload;
			PrivateKey redblobPrivateKey = (PrivateKey) redblobResponsePayload.object;
			KeyValueStructure redblobKeyValuestructure = (KeyValueStructure) redblobPrivateKey.keyBlock.keyValue;
			KeyMaterialField redblobKeyMaterialField = (KeyMaterialField) redblobKeyValuestructure.keyMaterial;
			byte[] redblobPrivateKeyBytes = DatatypeConverter.parseHexBinary(redblobKeyMaterialField.value);

			batchResponse.setRedblobWrappedKey(redblobPrivateKeyBytes);
			currentBatch += 1;
		}

		if (aesWrap) {
			ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[currentBatch];
			GetResponsePayload responsePayload = (GetResponsePayload) responseBatchItem.responsePayload;

			PrivateKey privateKey = (PrivateKey) responsePayload.object;

			KeyValueField keyValue = (KeyValueField) privateKey.keyBlock.keyValue;
			byte[] privateKeyBytes = DatatypeConverter.parseHexBinary(keyValue.value);

			batchResponse.setWrappedKey(privateKeyBytes);
			Values blockCipher = BlockCipherMode.Values.valueOf(wrapCipher);

			if (blockCipher == BlockCipherMode.Values.CBC) {
				batchResponse.setIv(iv);
			}
			currentBatch += 1;
		}

		return batchResponse;
	}

	public String create_activate_get_revoke_destroy_key_pair(String symmetricUid) throws KNetException {

		RequestMessage request = new RequestMessage();

		request.requestHeader = this.header;
		request.batchItems = new BatchItem[5];

		// create payload
		request.batchItems[0] = new RequestBatchItem();
		RequestBatchItem requestBatchItemCreate = (RequestBatchItem) request.batchItems[0];
		CreateKeyPairRequestPayload createRequestPayload = new CreateKeyPairRequestPayload();
		createRequestPayload.commonTemplateAttribute = new CommonTemplateAttribute();
		createRequestPayload.commonTemplateAttribute.attributes = new Attribute[2];
		createRequestPayload.commonTemplateAttribute.attributes[0] = new Attribute();
		createRequestPayload.commonTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.CryptographicAlgorithm);
		createRequestPayload.commonTemplateAttribute.attributes[0].attributeValue = new CryptographicAlgorithm(
				CryptographicAlgorithm.Values.RSA);
		createRequestPayload.commonTemplateAttribute.attributes[1] = new Attribute();
		createRequestPayload.commonTemplateAttribute.attributes[1].attributeName = new AttributeName(
				AttributeName.Values.CryptographicLength);
		createRequestPayload.commonTemplateAttribute.attributes[1].attributeValue = new CryptographicLength(2048);

		/* Fill the Private Key Template */
		createRequestPayload.privateKeyTemplateAttribute = new PrivateKeyTemplateAttribute();
		createRequestPayload.privateKeyTemplateAttribute.attributes = new Attribute[1];
		createRequestPayload.privateKeyTemplateAttribute.attributes[0] = new Attribute();
		createRequestPayload.privateKeyTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.CryptographicUsageMask);
		createRequestPayload.privateKeyTemplateAttribute.attributes[0].attributeValue = new CryptographicUsageMask(
				CryptographicUsageMask.Values.Sign);

		/* Fill the Public Key Template */
		createRequestPayload.publicKeyTemplateAttribute = new PublicKeyTemplateAttribute();
		createRequestPayload.publicKeyTemplateAttribute.attributes = new Attribute[1];
		createRequestPayload.publicKeyTemplateAttribute.attributes[0] = new Attribute();
		createRequestPayload.publicKeyTemplateAttribute.attributes[0].attributeName = new AttributeName(
				AttributeName.Values.CryptographicUsageMask);
		createRequestPayload.publicKeyTemplateAttribute.attributes[0].attributeValue = new CryptographicUsageMask(
				CryptographicUsageMask.Values.Verify);
		requestBatchItemCreate.operation = new Operation(Operation.Values.CreateKeyPair);
		requestBatchItemCreate.requestPayload = createRequestPayload;

		// activate
		request.batchItems[1] = new RequestBatchItem();
		RequestBatchItem requestBatchItemActivate = (RequestBatchItem) request.batchItems[1];
		ActivateRequestPayload activateRequestPayload = new ActivateRequestPayload();
		requestBatchItemActivate.operation = new Operation(Operation.Values.Activate);
		requestBatchItemActivate.requestPayload = activateRequestPayload;

		// get
		request.batchItems[2] = new RequestBatchItem();
		RequestBatchItem requestBatchItemGet = (RequestBatchItem) request.batchItems[2];
		GetRequestPayload getRequestPayload = new GetRequestPayload(null,
				new KeyFormatType(KeyFormatType.Values.KnetPrivateKey), null, null, null);
		requestBatchItemGet.operation = new Operation(Operation.Values.Get);
		requestBatchItemGet.requestPayload = getRequestPayload;

		// revoke payload
		request.batchItems[3] = new RequestBatchItem();
		RequestBatchItem requestBatchItemRevoke = (RequestBatchItem) request.batchItems[3];
		RevokeRequestPayload revokeRequestPayload = new RevokeRequestPayload(null,
				new RevocationReason(new RevocationReasonCode(RevocationReasonCode.Values.CessationOfOperation), null),
				null);
		requestBatchItemRevoke.operation = new Operation(Operation.Values.Revoke);
		requestBatchItemRevoke.requestPayload = revokeRequestPayload;

		// destroy payload
		request.batchItems[4] = new RequestBatchItem();
		RequestBatchItem requestBatchItemDestroy = (RequestBatchItem) request.batchItems[4];
		DestroyRequestPayload destroyRequesPayload = new DestroyRequestPayload(null);
		requestBatchItemDestroy.operation = new Operation(Operation.Values.Destroy);
		requestBatchItemDestroy.requestPayload = destroyRequesPayload;

		try {
			ResponseMessage response = this.client.sendRequest(request);
			checkMalformedResponse(response);

			ResponseBatchItem responseBatchItem = (ResponseBatchItem) response.batchItems[2];
			GetResponsePayload responsePayload = (GetResponsePayload) responseBatchItem.responsePayload;

			PrivateKey privateKey = (PrivateKey) responsePayload.object;
			KeyValueStructure keyValuestructure = (KeyValueStructure) privateKey.keyBlock.keyValue;
			KeyMaterialField keyMaterialField = (KeyMaterialField) keyValuestructure.keyMaterial;
			return keyMaterialField.value;
		} catch (EncodeException | DecodeException | SendRequestException | IOException e) {
			throw new KNetException(e.getMessage(), e.getCause());
		}
	}

	private java.security.PublicKey buildJavaECPublicKey(KeyValueStructure keyValueStructure) throws KNetException {
		TransparentECPublicKey keyMaterial = (TransparentECPublicKey) keyValueStructure.keyMaterial;

		// get w
		String qString = keyMaterial.qString.value;
		qString = qString.substring(2);
		BigInteger x = new BigInteger(1, DatatypeConverter.parseHexBinary(qString.substring(0, qString.length() / 2)));
		BigInteger y = new BigInteger(1, DatatypeConverter.parseHexBinary(qString.substring(qString.length() / 2)));
		ECPoint w = new ECPoint(x, y);

		// get spec
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
			parameters.init(new ECGenParameterSpec(RecommendedCurveNames.getName(keyMaterial.recommendedCurve.value)));
			ECParameterSpec paramSpec = parameters.<ECParameterSpec>getParameterSpec(ECParameterSpec.class);

			ECPublicKeySpec publicKeyParameters = new ECPublicKeySpec(w, paramSpec);
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			return keyFactory.generatePublic(publicKeyParameters);
		} catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException
				| NoSuchProviderException e) {
			throw new KNetException("Error building key: " + e.getMessage(), e.getCause());
		}
	}

	private java.security.PublicKey buildJavaRsaPublicKey(KeyValueStructure keyValueStructure) throws KNetException {
		TransparentRSAPublicKey keyMaterial = (TransparentRSAPublicKey) keyValueStructure.keyMaterial;
		BigInteger modulus = new BigInteger(keyMaterial.modulus.value, 16);
		BigInteger publicExponent = new BigInteger(keyMaterial.publicExponent.value, 16);
		RSAPublicKeySpec publicKeyParameters = new RSAPublicKeySpec(modulus, publicExponent);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(publicKeyParameters);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new KNetException("Error building key: " + e.getMessage(), e.getCause());
		}
	}

	private void checkMalformedResponse(ResponseMessage message) throws KNetException {
		int batchCount = message.batchItems.length;
		for (int i = 0; i < batchCount; i++) {
			ResponseBatchItem batchItem = (ResponseBatchItem) message.batchItems[i];
			if (batchItem.resultStatus.value.equals(ResultStatus.Values.OperationFailed.toString())) {
				String failMessage = batchItem.resultMessage.value;
				throw new KNetException("Response batch item " + i + " failed: " + failMessage, new Throwable());
			}
		}
	}

	private ResponseMessage sendMessage(RequestMessage message, DefaultClient client) throws KNetException {
		ResponseMessage response = null;
		try {
			response = client.sendRequest(message);
		} catch (EncodeException | DecodeException | SendRequestException | IOException e) {
			throw new KNetException("Failed to send request: " + e.getMessage(), e.getCause());
		}
		checkMalformedResponse(response);

		return response;
	}

}
