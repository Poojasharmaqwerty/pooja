pooja@pooja-pc:~/Downloads/mygov/oAuthMyGovFinal/src/test/java/in/mygov/policy$ cat ForceExpiredPasswordPolicyProviderTest.java 
package in.mygov.policy;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PolicyError;
import org.keycloak.models.KeycloakContext;

public class ForceExpiredPasswordPolicyProviderTest {

    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private KeycloakContext context;
    private KeycloakUriInfo uriInfo;

    @BeforeEach
    public void setup() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        context = mock(KeycloakContext.class);
        uriInfo = mock(KeycloakUriInfo.class);

        when(session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        when(realm.getName()).thenReturn("test-realm");
        when(user.getUsername()).thenReturn("test-user");
    }

    @Test
    public void testValidate_passwordExpired_returnsPolicyError() {
        long pastMillis = Instant.now().minus(400, ChronoUnit.DAYS).toEpochMilli();
        when(uriInfo.getPath()).thenReturn("/realms/test");
        when(user.getFirstAttribute("passwordLastUpdated")).thenReturn(String.valueOf(pastMillis));

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, "test-password");

        assertNotNull(error);
        assertEquals("force-expire-days", error.getMessage());
    }

    @Test
    public void testValidate_passwordValid_returnsNull() {
        long recentMillis = Instant.now().minus(100, ChronoUnit.DAYS).toEpochMilli();
        when(uriInfo.getPath()).thenReturn("/realms/test");
        when(user.getFirstAttribute("passwordLastUpdated")).thenReturn(String.valueOf(recentMillis));

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, "test-password");

        assertNull(error);
    }

    @Test
    public void testValidate_adminPath_returnsNull() {
        when(uriInfo.getPath()).thenReturn("/admin/some/path");

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, "test-password");

        assertNull(error);
    }

    @Test
    public void testValidate_userNull_returnsNull() {
        when(uriInfo.getPath()).thenReturn("/realms/test");

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, null, "test-password");

        assertNull(error);
    }

    @Test
    public void testValidate_passwordNull_returnsNull() {
        when(uriInfo.getPath()).thenReturn("/realms/test");

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, null);

        assertNull(error);
    }

    @Test
    public void testValidate_missingAttribute_returnsPolicyError() {
        when(uriInfo.getPath()).thenReturn("/realms/test");
        when(user.getFirstAttribute("passwordLastUpdated")).thenReturn(null);

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, "test-password");

        assertNotNull(error);
        assertEquals("force-expire-days", error.getMessage());
    }

    @Test
    public void testValidate_invalidDate_returnsPolicyError() {
        when(uriInfo.getPath()).thenReturn("/realms/test");
        when(user.getFirstAttribute("passwordLastUpdated")).thenReturn("not-a-number");

        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate(realm, user, "test-password");

        assertNotNull(error);
        assertEquals("force-expire-days", error.getMessage());
    }

    @Test
    public void testValidate_legacyFlow_returnsNull() {
        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        PolicyError error = provider.validate("some-user", "some-pass");
        assertNull(error);
    }

    @Test
    public void testParseConfig_validValue() {
        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        Object result = provider.parseConfig("180");
        assertTrue(result instanceof Integer);
        assertEquals(180, result);
    }

    @Test
    public void testParseConfig_invalidValue() {
        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        Object result = provider.parseConfig("invalid");
        assertTrue(result instanceof Integer);
        assertEquals(0, result);
    }

    @Test
    public void testClose_doesNotThrow() {
        ForceExpiredPasswordPolicyProvider provider = new ForceExpiredPasswordPolicyProvider(session, 365);
        assertDoesNotThrow(provider::close);
    }
}


