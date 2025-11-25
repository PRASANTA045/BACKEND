package com.coolcoder.security;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	@Value("${app.jwt.secret}")
	private String secret;

	@Value("${app.jwt.expiration-ms}")
	private long expiration;

	private Key getKey() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> resolver) {
		return resolver.apply(Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(token).getBody());
	}

	public String generateToken(UserDetails user) {
		return generateToken(Map.of(), user);
	}

	public String generateToken(Map<String, Object> claims, UserDetails user) {
		Date now = new Date();
		Date expiry = new Date(now.getTime() + expiration);

		return Jwts.builder().setClaims(claims).setSubject(user.getUsername()).setIssuedAt(now).setExpiration(expiry)
				.signWith(getKey(), SignatureAlgorithm.HS256).compact();
	}

	public boolean isValid(String token, UserDetails user) {
		return extractUsername(token).equals(user.getUsername())
				&& !extractClaim(token, Claims::getExpiration).before(new Date());
	}
}
