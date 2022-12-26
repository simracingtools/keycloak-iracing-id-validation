package de.bausdorf.simracing.keycloak.form;

/*-
 * #%L
 * de.bausdorf.simracing:keycloak-iracingid-validation
 * %%
 * Copyright (C) 2022 bausdorf engineering
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

import de.bausdorf.simracing.irdataapi.client.IrDataClient;
import de.bausdorf.simracing.irdataapi.client.impl.IrDataClientImpl;
import de.bausdorf.simracing.irdataapi.model.LoginRequestDto;
import de.bausdorf.simracing.irdataapi.model.MemberInfoDto;
import de.bausdorf.simracing.irdataapi.model.MembersInfoDto;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import javax.ws.rs.core.MultivaluedMap;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.keycloak.utils.StringUtil.isBlank;

@Slf4j
public class IRacingValidationFormAction implements FormAction, FormActionFactory {
    private static final String PROVIDER_ID = "organization-field-validation-action";
    private static final String FIRSTNAME_ATTR_KEY = "firstName";
    private static final String LASTNAME_ATTR_KEY = "lastName";

    public static final String IRACING_EMAIL_CONF_KEY = "iRacing.email";
    public static final String IRACING_PASSWORD_CONF_KEY = "iRacing.password";
    public static final String IRACING_ATTR_KEY_CONF_KEY = "iRacing.attribute";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
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
    private final IrDataClient dataClient = new IrDataClientImpl();
    private String iRemail = null;
    private String iRpass = null;

   @Override
    public String getDisplayType() {
       return "Signup iRacing ID Validation";
   }

    @Override
    public String getReferenceCategory() {
        return null;
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
        return true;
    }

    @Override
    public void buildPage(FormContext formContext, LoginFormsProvider loginFormsProvider) {

    }

    @Override
    public void validate(ValidationContext validationContext) {
        AuthenticatorConfigModel config = validationContext.getAuthenticatorConfig();
        iRemail = config.getConfig().get(IRACING_EMAIL_CONF_KEY);
        iRpass = config.getConfig().get(IRACING_PASSWORD_CONF_KEY);
        String iRacingIdAttributeKey = config.getConfig().get(IRACING_ATTR_KEY_CONF_KEY);

        MultivaluedMap<String, String> formData = validationContext.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();

        String eventError = Errors.INVALID_REGISTRATION;
        String iRacingId = formData.getFirst(iRacingIdAttributeKey);
        String firstName = formData.getFirst(FIRSTNAME_ATTR_KEY);
        String lastName = formData.getFirst(LASTNAME_ATTR_KEY);

        log.info("Try to validate iRacingId {} for {} {}", iRacingId, firstName, lastName);
        if (isBlank(iRacingId)) {
            log.error("Empty iRacingId");
            errors.add(new FormMessage(iRacingIdAttributeKey, "missingIRacingIdMessage"));
        } else {
            MemberInfoDto memberInfo = getIRacingMemberInfo(Long.parseLong(iRacingId));
            if(memberInfo == null) {
                log.error("Invalid iRacingId");
                errors.add(new FormMessage(iRacingIdAttributeKey, "invalidIRacingIdMessage"));
            } else {
                if (!checkMemberName(firstName, lastName, memberInfo.getDisplayName())) {
                    errors.add(new FormMessage(FIRSTNAME_ATTR_KEY, "nameNotMatchingMessage"));
                    errors.add(new FormMessage(LASTNAME_ATTR_KEY, "nameNotMatchingMessage"));
                }
            }
        }

        if (!errors.isEmpty()) {
            validationContext.error(eventError);
            validationContext.validationError(formData, errors);
        } else {
            validationContext.success();
        }

    }

    @Override
    public void success(FormContext formContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public String getHelpText() {
        return "Validates iRacing ID on signup.";
   }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public FormAction create(KeycloakSession keycloakSession) {

        return this;
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

    private void authorizeOnIracingService() {
        LoginRequestDto loginRequest = LoginRequestDto.builder()
                .email(iRemail)
                .password(iRpass)
                .build();
        log.info("authenticate to iRacing service");
        dataClient.authenticate(loginRequest);
    }

    private MemberInfoDto getIRacingMemberInfo(Long iRacingId) {
       Optional<MembersInfoDto> memberInfos = Optional.empty();
       try {
           memberInfos = Optional.of(dataClient.getMembersInfo(Collections.singletonList(iRacingId)));
       } catch(HttpClientErrorException clientErrorException) {
            if(clientErrorException.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                authorizeOnIracingService();
                memberInfos = Optional.of(dataClient.getMembersInfo(Collections.singletonList(iRacingId)));
            }
       }
       if(memberInfos.isPresent() && memberInfos.get().getMembers().length == 1) {
           log.info(memberInfos.get().getMembers()[0].toString());
           return memberInfos.get().getMembers()[0];
       }
       log.warn("No member info found");
       return null;
    }

    public boolean checkMemberName(String firstName, String lastName, String irDisplayName) {
        String[] firstNameParts = firstName.trim().split(" ");
        String[] lastNameParts = lastName.trim().split(" ");
        String[] irNameParts = irDisplayName.trim().split(" ");

        log.info("Check first name '{}', last name '{}' against iRacing name '{}'", firstNameParts, lastNameParts, irNameParts);
        AtomicBoolean firstNameCheck = new AtomicBoolean(false);
        Arrays.stream(firstNameParts).forEach(part -> firstNameCheck.set(Arrays.stream(irNameParts).anyMatch(iRPart -> iRPart.equalsIgnoreCase(part))));
        AtomicBoolean lastNameCheck = new AtomicBoolean(false);
        Arrays.stream(lastNameParts).forEach(part -> lastNameCheck.set(Arrays.stream(irNameParts).anyMatch(iRPart -> iRPart.equalsIgnoreCase(part))));
        log.info("Name check {}", firstNameCheck.get() && lastNameCheck.get() ? "OK" : "NOT OK");

        return firstNameCheck.get() && lastNameCheck.get();
    }
}
