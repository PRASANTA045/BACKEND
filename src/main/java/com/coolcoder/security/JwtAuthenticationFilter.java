package com.coolcoder.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.coolcoder.repository.UserRepository;
import com.coolcoder.security.JwtService;   // ⭐ REQUIRED IMPORT

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    // ⛔ Do NOT filter for login/register
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().startsWith("/api/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {

        String token = null;

        // ⭐ Check Cookie for JWT
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("jwt".equals(c.getName())) {
                    token = c.getValue();
                }
            }
        }

        // ⭐ Check Authorization header
        if (token == null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }
        }

        // ⭐ No token → move to next filter
        if (token == null) {
            chain.doFilter(request, response);
            return;
        }

        String email = jwtService.extractUsername(token);

        // ⭐ Ensure no prior authentication
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            var userOpt = userRepository.findByEmail(email);

            if (userOpt.isPresent()) {

                var user = userOpt.get();

                // ⭐ Extract role from JWT
                String role = jwtService.extractClaim(token, c -> c.get("role", String.class));

                // ⭐ Prevent null authority crash
                if (role == null || role.isBlank()) {
                    role = "USER";
                }

                var userDetails = User.withUsername(user.getEmail())
                        .password(user.getPassword())
                        .authorities(new SimpleGrantedAuthority(role))
                        .build();

                // ⭐ Validate token
                if (jwtService.isValid(token, user.getEmail())) {

                    var auth = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
        }

        chain.doFilter(request, response);
    }
}
