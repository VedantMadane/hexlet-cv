package io.hexlet.cv.controller;

import io.hexlet.cv.audit.AuditEventType;
import io.hexlet.cv.audit.AuditLogger;
import io.hexlet.cv.audit.AuditReason;
import io.hexlet.cv.audit.AuditSubject;
import io.hexlet.cv.security.TokenCookieService;
import io.hexlet.cv.security.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RefreshController {

    private final TokenService tokenService;
    private final TokenCookieService tokenCookieService;
    private final AuditLogger auditLogger;

    @PostMapping("/api/auth/refresh")
    public ResponseEntity<Void> refresh(@CookieValue(value = "refresh_token", required = false) String refreshToken,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        var subject = AuditSubject.current();

        if (refreshToken == null) {
            auditLogger.logFailure(AuditEventType.TOKEN_REFRESH, subject, AuditReason.TOKEN_MISSING, request);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            var refreshed = tokenService.refresh(refreshToken);
            var cookies = tokenCookieService.buildCookies(refreshed.tokens());
            response.addHeader(HttpHeaders.SET_COOKIE, cookies.access().toString());
            response.addHeader(HttpHeaders.SET_COOKIE, cookies.refresh().toString());
            auditLogger.logSuccess(AuditEventType.TOKEN_REFRESH, refreshed.subject(), request);
            return ResponseEntity.noContent().build();
        } catch (BadCredentialsException e) {
            var expired = tokenCookieService.buildExpiredCookies();
            response.addHeader(HttpHeaders.SET_COOKIE, expired.access().toString());
            response.addHeader(HttpHeaders.SET_COOKIE, expired.refresh().toString());
            auditLogger.logFailure(AuditEventType.TOKEN_REFRESH, subject, AuditReason.TOKEN_INVALID, request);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
