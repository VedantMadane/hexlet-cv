package io.hexlet.cv.controller;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.hexlet.cv.model.User;
import io.hexlet.cv.model.enums.RoleType;
import io.hexlet.cv.repository.UserRepository;
import io.hexlet.cv.support.TokenTestHelper;
import jakarta.servlet.http.Cookie;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RefreshControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private TokenTestHelper tokenHelper;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        var user = new User();
        user.setEmail("test@gmail.com");
        user.setEncryptedPassword(encoder.encode("test_password"));
        user.setFirstName("firstName");
        user.setLastName("lastName");
        user.setRole(RoleType.CANDIDATE);
        userRepository.save(user);
    }

    private String cookieValue(MvcResult result, String name) {
        return java.util.Arrays.stream(result.getResponse().getCookies())
                .filter(c -> c.getName().equals(name))
                .findFirst()
                .map(Cookie::getValue)
                .orElseThrow(() -> new AssertionError("cookie " + name + " not found"));
    }

    private MvcResult loginAs(String email, String password) throws Exception {
        var body = """
            {"email": "%s", "password": "%s"}
            """.formatted(email, password);
        return mockMvc.perform(post("/users/sign_in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().is3xxRedirection())
                .andReturn();
    }

    @Test
    void refreshTokenCannotAuthenticateProtectedEndpoint() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String refreshToken = cookieValue(login, "refresh_token");

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", refreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void accessTokenCannotBeUsedAtRefreshEndpoint() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String accessToken = cookieValue(login, "access_token");

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", accessToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshReturnsNewAccessAndRefreshTokens() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String refreshToken = cookieValue(login, "refresh_token");

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isNoContent())
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
                        Matchers.hasItem(Matchers.containsString("access_token"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
                        Matchers.hasItem(Matchers.containsString("refresh_token"))));
    }

    @Test
    void expiredOrGarbageRefreshTokenIsRejected() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "not-a-real-jwt")))
                .andExpect(status().isUnauthorized());
    }

    // 7.1 (обязательный): повторное предъявление уже обменянного refresh гасит всё семейство.
    @Test
    void replayOfUsedRefreshTokenRevokesWholeFamily() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String firstRefresh = cookieValue(login, "refresh_token");

        var rotated = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", firstRefresh)))
                .andExpect(status().isNoContent())
                .andReturn();
        String successorRefresh = cookieValue(rotated, "refresh_token");

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", firstRefresh)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", successorRefresh)))
                .andExpect(status().isUnauthorized());
    }

    // 7.3 (обязательный): после logout access-токен умирает немедленно.
    @Test
    void accessTokenIsDeadImmediatelyAfterLogout() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String access = cookieValue(login, "access_token");
        String refresh = cookieValue(login, "refresh_token");

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/users/sign_out")
                        .cookie(new Cookie("refresh_token", refresh)))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access)))
                .andExpect(status().isUnauthorized());
    }

    // 7.4: logout гасит только предъявленную сессию, другие устройства живы.
    @Test
    void logoutRevokesOnlyPresentedSession() throws Exception {
        var login1 = loginAs("test@gmail.com", "test_password");
        String access1 = cookieValue(login1, "access_token");
        String refresh1 = cookieValue(login1, "refresh_token");

        var login2 = loginAs("test@gmail.com", "test_password");
        String access2 = cookieValue(login2, "access_token");
        String refresh2 = cookieValue(login2, "refresh_token");

        mockMvc.perform(post("/users/sign_out")
                        .cookie(new Cookie("refresh_token", refresh1)))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access1)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access2)))
                .andExpect(status().isOk());
    }

    // 7.5: детект кражи гасит и access-токены семейства.
    @Test
    void replayRevokesAccessTokensOfFamily() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String firstRefresh = cookieValue(login, "refresh_token");

        var rotated = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", firstRefresh)))
                .andExpect(status().isNoContent())
                .andReturn();
        String rotatedAccess = cookieValue(rotated, "access_token");

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", firstRefresh)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", rotatedAccess)))
                .andExpect(status().isUnauthorized());
    }

    // 7.6: обычная цепочка ротаций — каждый refresh даёт новый refresh-токен.
    @Test
    void refreshIssuesNewTokensAlongChain() throws Exception {
        var login = loginAs("test@gmail.com", "test_password");
        String firstRefresh = cookieValue(login, "refresh_token");

        var second = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", firstRefresh)))
                .andExpect(status().isNoContent())
                .andReturn();
        String secondRefresh = cookieValue(second, "refresh_token");

        var third = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", secondRefresh)))
                .andExpect(status().isNoContent())
                .andReturn();
        String thirdRefresh = cookieValue(third, "refresh_token");

        assertNotEquals(firstRefresh, secondRefresh);
        assertNotEquals(secondRefresh, thirdRefresh);
    }

    // 7.10: tokenVersion остаётся глобальным kill switch.
    @Test
    void tokenVersionStillKillsAllSessions() throws Exception {
        var login1 = loginAs("test@gmail.com", "test_password");
        String access1 = cookieValue(login1, "access_token");

        var login2 = loginAs("test@gmail.com", "test_password");
        String access2 = cookieValue(login2, "access_token");

        new TransactionTemplate(transactionManager).executeWithoutResult(
                status -> userRepository.incrementTokenVersion("test@gmail.com"));

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access1)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/account/knowledge")
                        .cookie(new Cookie("access_token", access2)))
                .andExpect(status().isUnauthorized());
    }

    // 7.9: фаза 1 мягко переводит токен старого формата на новую схему.
    @Test
    void legacyRefreshTokenIsMigratedToRotatingSession() throws Exception {
        String legacyToken = tokenHelper.legacyRefreshToken("test@gmail.com", 0);

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", legacyToken)))
                .andExpect(status().isNoContent())
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE,
                        Matchers.hasItem(Matchers.containsString("refresh_token"))));
    }
}
