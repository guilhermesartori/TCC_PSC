package br.ufsc.tsp.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JWTManager {

	@Autowired
	private ParameterEncryptor parameterEncryptor;

	private static final Algorithm ALGORITHM = Algorithm.HMAC256(SystemKey.getKey());
	private static final long ACCESS_TOKEN_VALIDITY_MS = 8 * 60 * 60 * 1000;
	private static final String SALT = "PSC";
	public static final String ROLES_CLAIM = "roles";
	public static final String ACCESS_KEY_CLAIM = "accessKey";
	

	public static class DecodedJWTManager {

		private final DecodedJWT decodedJWT;

		public DecodedJWTManager(DecodedJWT decodedJwt) {
			this.decodedJWT = decodedJwt;
		}

		public String getUsername() {
			return decodedJWT.getSubject();
		}

		public Collection<SimpleGrantedAuthority> getAuthorities() {
			final var roles = decodedJWT.getClaim(ROLES_CLAIM).asArray(String.class);
			final var authorities = new ArrayList<SimpleGrantedAuthority>();
			Arrays.stream(roles).forEach(role -> {
				authorities.add(new SimpleGrantedAuthority(role));
			});
			return authorities;
		}

		public String getAccessKey() {
			return decodedJWT.getClaim(ACCESS_KEY_CLAIM).asString();
		}

	}

	public String createAccessToken(String username, String password, String issuer, List<String> roles) {
		final var currTime = System.currentTimeMillis();
		final var encodedAccessKey = parameterEncryptor.encryptKey(username + password + SALT);
		final var accessToken = JWT.create().withSubject(username)
				.withExpiresAt(new Date(currTime + ACCESS_TOKEN_VALIDITY_MS)).withIssuer(issuer)
				.withClaim(ROLES_CLAIM, roles).withClaim(ACCESS_KEY_CLAIM, encodedAccessKey).sign(ALGORITHM);
		return accessToken;
	}

	public DecodedJWTManager decode(String token) {
		final var jwtVerifier = JWT.require(ALGORITHM).build();
		final var decodedJWT = jwtVerifier.verify(token);
		return new DecodedJWTManager(decodedJWT);
	}
}
