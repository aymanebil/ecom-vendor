package com.aymane.ecom.multivendor.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.List;

import static com.aymane.ecom.multivendor.config.JWT_CONSTANT.*;

public class JwtTokenValidator extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = request.getHeader(JWT_TOKEN_HEADER);
        if (jwtToken != null && jwtToken.startsWith(JWT_BEARER)) {
            jwtToken = jwtToken.substring(JWT_BEARER.length());
            try {
                final SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
                final Claims claims = Jwts.parser().setSigningKey(key).build()
                        .parseClaimsJws(jwtToken).getBody();

                final String email = String.valueOf(claims.get("email"));
                final String authorities = String.valueOf(claims.get("authorities"));

                final List<GrantedAuthority> grantedAuthorities =
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

                final Authentication authentication =
                        new UsernamePasswordAuthenticationToken(email, null, grantedAuthorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (final Exception e) {
                throw new BadCredentialsException("Invalid JWT token");
            }
        }
        filterChain.doFilter(request, response);
    }
}
