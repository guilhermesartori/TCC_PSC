package br.ufsc.tsp.utility;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTManager {

	private static final Algorithm ALGORITHM = Algorithm.HMAC256("secret".getBytes());;
	private static final long ACCESS_TOKEN_VALIDITY_MS = 10 * 60 * 1000;
	private static final long REFRESH_TOKEN_VALIDITY_MS = 30 * 60 * 1000;
	private static final String ROLES_CLAIM = "roles";

	public static class DecodedJWTManager {

		private final DecodedJWT decodedJWT;

		public DecodedJWTManager(DecodedJWT decodedJwt) {
			this.decodedJWT = decodedJwt;
		}

		public String getUsername() {
			return decodedJWT.getSubject();
		}

		public Collection<SimpleGrantedAuthority> getAuthorities() {
			var roles = decodedJWT.getClaim(ROLES_CLAIM).asArray(String.class);
			var authorities = new ArrayList<SimpleGrantedAuthority>();
			Arrays.stream(roles).forEach(role -> {
				authorities.add(new SimpleGrantedAuthority(role));
			});
			return authorities;
		}

	}

	public String createAccessToken(String username, String issuer, List<String> roles) {
		var accessToken = JWT.create().withSubject(username)
				.withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_MS)).withIssuer(issuer)
				.withClaim(ROLES_CLAIM, roles).sign(ALGORITHM);
		return accessToken;
	}

	public String createRefreshToken(String username, String issuer) {
		var refreshToken = JWT.create().withSubject(username)
				.withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY_MS)).withIssuer(issuer)
				.sign(ALGORITHM);
		return refreshToken;
	}

	public DecodedJWTManager decode(String token) {
		var jwtVerifier = JWT.require(ALGORITHM).build();
		var decodedJWT = jwtVerifier.verify(token);
		return new DecodedJWTManager(decodedJWT);
	}
}
