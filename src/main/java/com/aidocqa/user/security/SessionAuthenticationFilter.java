package com.aidocqa.user.security;

import com.aidocqa.user.entity.User;
import com.aidocqa.user.repository.UserRepository;
import com.aidocqa.user.service.SessionService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private final SessionService sessionService;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String tokenOrSessionId = extractTokenOrSessionId(request);

        if (tokenOrSessionId != null && !tokenOrSessionId.isBlank() && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                User user = null;
                String activeSessionId = null;

                // 1. Try treating as JWT token first if dots exist
                if (tokenOrSessionId.contains(".")) {
                    try {
                        Claims claims = jwtService.extractAllClaims(tokenOrSessionId);
                        String email = claims.getSubject();
                        if (email != null && !jwtService.isTokenExpired(tokenOrSessionId)) {
                            Optional<User> uOpt = userRepository.findByEmail(email);
                            if (uOpt.isPresent()) {
                                user = uOpt.get();
                                activeSessionId = claims.get("sessionId", String.class);
                            }
                        }
                    } catch (Exception ignored) {}
                }

                // 2. If not JWT or JWT fallback, validate via active session store
                if (user == null) {
                    user = sessionService.validateAndSlideSession(tokenOrSessionId);
                    activeSessionId = tokenOrSessionId;
                }

                if (user != null) {
                    UserPrincipal principal = new UserPrincipal(user, activeSessionId);
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            principal,
                            null,
                            principal.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (Exception e) {
                log.debug("Auth validation check failed: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenOrSessionId(HttpServletRequest request) {
        // 1. Check Authorization: Bearer <token/sessionId>
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }

        // 2. Check X-Session-Token or X-Session-Id header
        String sessionHeader = request.getHeader("X-Session-Token");
        if (sessionHeader != null && !sessionHeader.isBlank()) {
            return sessionHeader.trim();
        }

        String sessionIdHeader = request.getHeader("X-Session-Id");
        if (sessionIdHeader != null && !sessionIdHeader.isBlank()) {
            return sessionIdHeader.trim();
        }

        // 3. Check Cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("AIDOC_SESSION".equalsIgnoreCase(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}
