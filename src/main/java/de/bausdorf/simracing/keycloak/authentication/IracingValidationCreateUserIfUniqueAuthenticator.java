package de.bausdorf.simracing.keycloak.authentication;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static de.bausdorf.simracing.keycloak.authentication.IracingValidationCreateUserIfUniqueAuthenticatorFactory.IRACING_ATTR_KEY_CONF_KEY;

@Slf4j
public class IracingValidationCreateUserIfUniqueAuthenticator extends AbstractIdpAuthenticator {
    @Override
    protected void actionImpl(AuthenticationFlowContext authenticationFlowContext, SerializedBrokeredIdentityContext serializedBrokeredIdentityContext, BrokeredIdentityContext brokeredIdentityContext) {

    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
            context.attempted();
            return;
        }

        String username = getUsername(context, serializedCtx, brokerContext);
        if (username == null) {
            ServicesLogger.LOGGER.resetFlow(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        List<FormMessage> errors = new ArrayList<>();

        String eventError = Errors.INVALID_REGISTRATION;

        ExistingUserInfo duplication = null;
        try {
            duplication = checkExistingUser(context, serializedCtx, brokerContext);
        } catch (IllegalArgumentException e) {
            errors.add(new FormMessage("iRacingId", e.getMessage()));
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
        }

        if (duplication == null) {
            log.debug("No duplication detected. Creating account for user '{}' and linking with identity provider '{}'.",
                    username, brokerContext.getIdpConfig().getAlias());

            UserModel federatedUser = session.users().addUser(realm, username);
            federatedUser.setEnabled(true);

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
                if (!UserModel.USERNAME.equalsIgnoreCase(attr.getKey())) {
                    federatedUser.setAttribute(attr.getKey(), attr.getValue());
                }
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            if (config != null && Boolean.parseBoolean(config.getConfig().get(IracingValidationCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION))) {
                log.debug("User '{}' required to update password", federatedUser.getUsername());
                federatedUser.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            }

//            userRegisteredSuccess(context, federatedUser, serializedCtx, brokerContext);

            context.setUser(federatedUser);
            context.getAuthenticationSession().setAuthNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            log.debug("Duplication detected. There is already existing user with {} '{}' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

            // Set duplicated user, so next authenticators can deal with it
            context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
            //Only show error message if the authenticator was required
            if (context.getExecution().isRequired()) {
                Response challengeResponse = context.form()
                        .setError(Messages.FEDERATED_IDENTITY_EXISTS, duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                        .createErrorPage(Response.Status.CONFLICT);
                context.challenge(challengeResponse);
                context.getEvent()
                        .user(duplication.getExistingUserId())
                        .detail("existing_" + duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                        .removeDetail(Details.AUTH_METHOD)
                        .removeDetail(Details.AUTH_TYPE)
                        .error(Errors.FEDERATED_IDENTITY_EXISTS);
            } else {
                context.attempted();
            }
        }
    }

    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(context.getRealm(), brokerContext.getEmail());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        String iRacingIdAttributeKey = context.getAuthenticatorConfig().getConfig().get(IRACING_ATTR_KEY_CONF_KEY);

        String iRacingId = serializedCtx.getAttributeStream("iRacingId").findFirst().orElse("");

        UserModel existingUser = context.getSession().users().getUsersStream(context.getRealm(), false)
                .filter(user -> {
                    String existingIRacingId = user.getAttributeStream(iRacingIdAttributeKey).findFirst().orElse("");
                    return existingIRacingId.isEmpty() || existingIRacingId.equals(iRacingId);
                })
                .findFirst().orElse(null);
        if (existingUser != null) {
            throw new IllegalArgumentException("iRacing id " + iRacingId + " already registered");
        }

        return null;
    }

    protected String getUsername(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }
}
