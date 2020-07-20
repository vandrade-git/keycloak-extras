package org.vandrade.keycloak;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationUserCreation;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import org.vandrade.keycloak.reference.Constants;

/**
 * @author vandrade
 */
public class EnhancedUserRegistration extends RegistrationUserCreation {
    // consts >>
    public static final String PROVIDER_ID = "enhanced-user-registration";
    // << consts

    // FormAction >>
    @Override
    public void validate(ValidationContext validationContext) {
        MultivaluedMap<String, String> formData = validationContext.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();

        validationContext.getEvent().detail(Details.REGISTER_METHOD, "form");

        // email
        String email = formData.getFirst(RegistrationPage.FIELD_EMAIL);
        validationContext.getEvent().detail(Details.EMAIL, email);

        // confirm email
        String confirmEmail = formData.getFirst(Constants.RegistrationPage.FIELD_CONFIRM_EMAIL);
        validationContext.getEvent().detail(Details.EMAIL, confirmEmail);

        // username
        String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        validationContext.getEvent().detail(Details.USERNAME, username);

        String usernameField = RegistrationPage.FIELD_USERNAME;
        if (validationContext.getRealm().isRegistrationEmailAsUsername()) {
            validationContext.getEvent().detail(Details.USERNAME, email);

            {
                if (Validation.isBlank(email)) {
                    errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
                } else if (!Validation.isEmailValid(email)) {
                    formData.remove(Validation.FIELD_EMAIL);
                    errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Constants.Messages.MALFORMED_EMAIL));
                }

                if (!email.equals(confirmEmail)) {
                    formData.remove(Constants.Validation.FIELD_CONFIRM_EMAIL);
                    errors.add(new FormMessage(Constants.RegistrationPage.FIELD_CONFIRM_EMAIL, Constants.Messages.NOT_MATCH_EMAIL));
                }

                if (errors.size() > 0) {
                    validationContext.error(Errors.INVALID_REGISTRATION);
                    validationContext.validationError(formData, errors);

                    return;
                }
            }

            if (!validationContext.getRealm().isDuplicateEmailsAllowed() && validationContext.getSession().users().getUserByEmail(email, validationContext.getRealm()) != null) {
                formData.remove(Validation.FIELD_EMAIL);
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.EMAIL_EXISTS));
                validationContext.error(Errors.EMAIL_IN_USE);
                validationContext.validationError(formData, errors);

                return;
            }
        } else {
            if (Validation.isBlank(username)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.MISSING_USERNAME));

                validationContext.error(Errors.INVALID_REGISTRATION);
                validationContext.validationError(formData, errors);

                return;
            }

            if (validationContext.getSession().users().getUserByUsername(username, validationContext.getRealm()) != null) {
                formData.remove(Validation.FIELD_USERNAME);
                errors.add(new FormMessage(usernameField, Messages.USERNAME_EXISTS));

                validationContext.error(Errors.USERNAME_IN_USE);
                validationContext.validationError(formData, errors);

                return;
            }

        }

        validationContext.success();
    }
    // << FormAction

    // FormActionFactory >>
    @Override
    public String getDisplayType() {
        return "Enhanced User Registration";
    }

    @Override
    public String getHelpText() {
        return "This action must always be first! Validates the username of the user in validation phase. In success phase, this will create the user in the database.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    // << FormActionFactory
}
