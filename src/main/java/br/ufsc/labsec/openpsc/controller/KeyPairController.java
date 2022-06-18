package br.ufsc.labsec.openpsc.controller;

import java.net.URI;
import java.util.ArrayList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import br.ufsc.labsec.openpsc.data.request.KeyPairGenerationRequest;
import br.ufsc.labsec.openpsc.data.request.SignatureRequest;
import br.ufsc.labsec.openpsc.data.request.SignatureVerificationRequest;
import br.ufsc.labsec.openpsc.data.response.ErrorMessageResponse;
import br.ufsc.labsec.openpsc.data.response.KeyResponse;
import br.ufsc.labsec.openpsc.data.response.SignatureResponse;
import br.ufsc.labsec.openpsc.data.response.SignatureVerificationResponse;
import br.ufsc.labsec.openpsc.service.KeyPairService;
import br.ufsc.labsec.openpsc.service.exception.KeyPairServiceException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping(path = "key")
public class KeyPairController {

  private final KeyPairService keyPairService;

  /**
   * @param keyPairService
   */
  @Autowired
  public KeyPairController(KeyPairService keyPairService) {
    super();
    this.keyPairService = keyPairService;
  }

  @Operation(responses = {
      @ApiResponse(responseCode = "200",
          content = @Content(
              array = @ArraySchema(schema = @Schema(implementation = KeyResponse.class)),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @SecurityRequirement(name = "user")
  @GetMapping
  public ResponseEntity<Object> getKeys(
      @RequestParam(required = false, name = "keyName") String keyName) {
    try {
      final var username = SecurityContextHolder.getContext().getAuthentication().getName();
      final var body = new ArrayList<KeyResponse>();
      if (keyName != null && !keyName.isBlank()) {
        final var keyPair = keyPairService.getKeyPairByKeyName(username, keyName);
        final var keyAlgorithm = keyPair.getKeyAlgorithm();
        final var keyParameter = keyPair.getKeyParameter();
        final var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
        final var keyNameResponse = keyPair.getKeyName();
        final var publicKey =
            keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm, keyParameter);
        final var keyResponse =
            new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey, keyNameResponse);
        body.add(keyResponse);
      } else {
        final var keyPairs = keyPairService.getKeyPairs(username);
        for (final var keyPair : keyPairs) {
          final var keyAlgorithm = keyPair.getKeyAlgorithm();
          final var keyParameter = keyPair.getKeyParameter();
          final var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
          final var keyNameResponse = keyPair.getKeyName();
          final var publicKey =
              keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm, keyParameter);
          final var keyResponse =
              new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey, keyNameResponse);
          body.add(keyResponse);
        }
      }
      return ResponseEntity.ok().body(body);
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Throwable e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

  @Operation(responses = {
      @ApiResponse(responseCode = "201",
          headers = @Header(name = "Location", description = "URI to the key created",
              schema = @Schema(type = "string"))),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @SecurityRequirement(name = "user")
  @PostMapping
  public ResponseEntity<Object> createKeyPair(@RequestBody KeyPairGenerationRequest request) {
    try {
      final var username = SecurityContextHolder.getContext().getAuthentication().getName();
      final var encodingKey =
          (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
      final var keyPair = keyPairService.createKeyPair(username, encodingKey,
          request.getKeyAlgorithm(), request.getKeyParameter(), request.getKeyName());
      final var pathToCreatedKey = String.format("/key/%s", keyPair.getUniqueIdentifier());
      final var uriString =
          ServletUriComponentsBuilder.fromCurrentContextPath().path(pathToCreatedKey).toUriString();
      final var uri = URI.create(uriString);
      return ResponseEntity.created(uri).build();
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Throwable e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

  @Operation(responses = {
      @ApiResponse(responseCode = "200",
          content = @Content(schema = @Schema(implementation = SignatureResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @SecurityRequirement(name = "user")
  @PostMapping(path = "{keyUniqueIdentifier}/sign")
  public ResponseEntity<Object> sign(@RequestBody SignatureRequest request,
      @PathVariable("keyUniqueIdentifier") String uniqueIdentifier) {
    try {
      final var username = SecurityContextHolder.getContext().getAuthentication().getName();
      final var accessKey =
          (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
      final var signature = keyPairService.sign(username, accessKey, request.getBase64EncodedData(),
          uniqueIdentifier, request.getHashingAlgorithm());

      final var keyPair = keyPairService.getKeyPair(username, uniqueIdentifier);
      final var publicKey = keyPairService.getPublicKey(keyPair.getPublicKey(),
          keyPair.getKeyAlgorithm(), keyPair.getKeyParameter());

      final var body = new SignatureResponse(signature, uniqueIdentifier, publicKey);
      return ResponseEntity.ok().body(body);
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Throwable e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

  @Operation(responses = {

      @ApiResponse(responseCode = "204"),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @SecurityRequirement(name = "user")
  @DeleteMapping(path = "{keyUniqueIdentifier}")
  public ResponseEntity<Object> deleteKeyPair(
      @PathVariable("keyUniqueIdentifier") String uniqueIdentifier) {
    try {
      final var username = SecurityContextHolder.getContext().getAuthentication().getName();
      final var encodingKey =
          (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
      keyPairService.deleteKeyPair(username, encodingKey, uniqueIdentifier);
      return ResponseEntity.noContent().build();
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Throwable e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

  @Operation(responses = {
      @ApiResponse(responseCode = "200",
          content = @Content(schema = @Schema(implementation = KeyResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @SecurityRequirement(name = "user")
  @GetMapping(path = "{keyUniqueIdentifier}")
  public ResponseEntity<Object> getKey(
      @PathVariable("keyUniqueIdentifier") String keyUniqueIdentifier) {
    try {
      final var username = SecurityContextHolder.getContext().getAuthentication().getName();
      final var keyPair = keyPairService.getKeyPair(username, keyUniqueIdentifier);
      final var keyAlgorithm = keyPair.getKeyAlgorithm();
      final var keyParameter = keyPair.getKeyParameter();
      final var keyPairUniqueIdentifier = keyPair.getUniqueIdentifier();
      final var keyName = keyPair.getKeyName();
      final var publicKey =
          keyPairService.getPublicKey(keyPair.getPublicKey(), keyAlgorithm, keyParameter);
      final var body = new KeyResponse(keyPairUniqueIdentifier, keyAlgorithm, publicKey, keyName);
      return ResponseEntity.ok().body(body);
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Throwable e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

  @Operation(responses = {
      @ApiResponse(responseCode = "200",
          content = @Content(schema = @Schema(implementation = SignatureVerificationResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "400",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE)),
      @ApiResponse(responseCode = "500",
          content = @Content(schema = @Schema(implementation = ErrorMessageResponse.class),
              mediaType = MediaType.APPLICATION_JSON_VALUE))})
  @PostMapping(path = "{keyUniqueIdentifier}/verify-signature")
  public ResponseEntity<Object> verify(
      @PathVariable("keyUniqueIdentifier") String keyUniqueIdentifier,
      @RequestBody SignatureVerificationRequest request) {
    try {
      final var validSignature =
          keyPairService.verifySignature(keyUniqueIdentifier, request.getBase64EncodedData(),
              request.getBase64EncodedSignature(), request.getSignatureAlgorithm());
      final var body = new SignatureVerificationResponse(validSignature);
      return ResponseEntity.ok().body(body);
    } catch (KeyPairServiceException e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.badRequest().body(body);
    } catch (Exception e) {
      final var body = new ErrorMessageResponse(e.getMessage());
      return ResponseEntity.internalServerError().body(body);
    }
  }

}
