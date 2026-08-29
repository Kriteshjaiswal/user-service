package com.aidocqa.user.security;

import com.aidocqa.user.entity.User;
import com.aidocqa.user.service.SessionService;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private final SessionService sessionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String sessionId = extractSessionId(request);

        if (sessionId != null && !sessionId.isBlank() && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                User user = sessionService.validateAndSlideSession(sessionId);
                UserPrincipal principal = new UserPrincipal(user, sessionId);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        principal.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } catch (Exception e) {
                log.debug("Session validation check failed: {}", e.getMessage());
                // Do not fail immediately; let Spring Security authorization rule decide for protected endpoints
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractSessionId(HttpServletRequest request) {
        // 1. Check Authorization: Bearer <sessionId>
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
