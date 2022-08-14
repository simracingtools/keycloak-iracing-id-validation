package de.bausdorf.simracing.keycloak.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class IracingValidationCreateUserIfUniqueAuthenticatorFactory implements AuthenticatorFactory {
    private static final String PROVIDER_ID = "idp-create-user-if-unique-and-validate";
    public static final String REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION = "require.password.update.after.registration";    public static final String IRACING_EMAIL_CONF_KEY = "iRacing.email";
    public static final String IRACING_PASSWORD_CONF_KEY = "iRacing.password";
    public static final String IRACING_ATTR_KEY_CONF_KEY = "iRacing.attribute";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty changePasswordProperty = new ProviderConfigProperty();
        changePasswordProperty.setName(REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION);
        changePasswordProperty.setLabel("Require Password Update After Registration");
        changePasswordProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        changePasswordProperty.setHelpText("If this option is true and new user is successfully imported from Identity Provider to Keycloak (there is no duplicated email or username detected in Keycloak DB), then this user is required to update his password");
        configProperties.add(changePasswordProperty);

        ProviderConfigProperty userProperty = new ProviderConfigProperty();
        userProperty.setName(IRACING_EMAIL_CONF_KEY);
        userProperty.setLabel("iRacing email");
        userProperty.setType(ProviderConfigProperty.STRING_TYPE);
        userProperty.setHelpText("Email address used to log into iRacing service.");

        ProviderConfigProperty passProperty = new ProviderConfigProperty();
        passProperty.setName(IRACING_PASSWORD_CONF_KEY);
        passProperty.setLabel("iRacing password");
        passProperty.setType(ProviderConfigProperty.STRING_TYPE);
        passProperty.setHelpText("Password used to log into iRacing service.");

        ProviderConfigProperty keyProperty = new ProviderConfigProperty();
        keyProperty.setName(IRACING_ATTR_KEY_CONF_KEY);
        keyProperty.setLabel("User profile iRacing ID attribute name");
        keyProperty.setType(ProviderConfigProperty.STRING_TYPE);
        keyProperty.setHelpText("Key of the user profile attribute the iRacing ID is read from.");

        configProperties.add(userProperty);
        configProperties.add(passProperty);
        configProperties.add(keyProperty);
    }

    static IracingValidationCreateUserIfUniqueAuthenticator SINGLETON = new IracingValidationCreateUserIfUniqueAuthenticator();

    @Override
    public String getDisplayType() {
        return "Create iRacing user if unique";
    }

    @Override
    public String getReferenceCategory() {
        return "createUserIfUnique";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Detect if there is existing Keycloak account with same email like identity provider. If no, create new user and validate iRacing ID";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
