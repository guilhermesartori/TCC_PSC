package br.ufsc.labsec.openpsc.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import br.ufsc.labsec.openpsc.entity.enums.Authority;
import br.ufsc.labsec.openpsc.service.JWTManager;
import br.ufsc.labsec.openpsc.service.SystemKey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

@SpringBootTest
public class TestJWTManager {

	@Autowired
	private JWTManager jwtManager;

	private static final String USERNAME = "test";
	private static final String PASSWORD = "test";
	private static final String ISSUER = "test";
	private static final String ROLE = Authority.USER.name();
	private static final List<String> ROLES = new ArrayList<>();

	@BeforeAll
	public static void createJwtManager() {
		ROLES.add(ROLE);
	}

	@Test
	public void createAccessToken() {
		final var verifier = JWT.require(Algorithm.HMAC256(SystemKey.getKey())).build();

		final var token = jwtManager.createAccessToken(USERNAME, PASSWORD, ISSUER, ROLES);

		assertNotNull(token);
		assertDoesNotThrow(() -> {
			verifier.verify(token);
		});
		final var decodedJWT = verifier.verify(token);

		final var rolesClaim = decodedJWT.getClaim(JWTManager.ROLES_CLAIM);
		assertFalse(rolesClaim.isNull());
		final var roles = rolesClaim.asArray(String.class);
		assertNotNull(roles);
		assertTrue(Set.of(roles).contains(ROLE));

		final var issuer = decodedJWT.getIssuer();
		assertNotNull(issuer);
		assertEquals(ISSUER, issuer);

		final var subject = decodedJWT.getSubject();
		assertNotNull(subject);
		assertEquals(USERNAME, subject);

		final var accessKeyClaim = decodedJWT.getClaim(JWTManager.ACCESS_KEY_CLAIM);
		assertFalse(accessKeyClaim.isNull());
		final var accessKey = accessKeyClaim.asString();
		assertNotNull(accessKey);

		final var expiresAt = decodedJWT.getExpiresAt();
		assertNotNull(expiresAt);
	}

	@Test
	public void decode() {
		final var token = jwtManager.createAccessToken(USERNAME, PASSWORD, ISSUER, ROLES);

		final var decodedJwtManager = jwtManager.decode(token);

		assertEquals(USERNAME, decodedJwtManager.getUsername());
		assertNotNull(decodedJwtManager.getAccessKey());
		for (final var role : ROLES)
			assertTrue(decodedJwtManager.getAuthorities().contains(new SimpleGrantedAuthority(role)));
	}

}
