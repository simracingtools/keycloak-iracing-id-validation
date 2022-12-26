package de.bausdorf.simracing.keycloak;


import de.bausdorf.simracing.keycloak.form.IRacingValidationFormAction;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IRacingValidationFormActionTest {

    private final IRacingValidationFormAction action = new IRacingValidationFormAction();

    @ParameterizedTest
    @MethodSource("testNames")
    void testMemberNameCheck(String firstName, String lastName, String displayName, boolean expectedResult) {
        assertEquals(action.checkMemberName(firstName, lastName, displayName), expectedResult);
    }

    private static Stream<Arguments> testNames() {
        return Stream.of(
                Arguments.of("Ayllas", "de Vries", "Ayllas de Vries", true),
                Arguments.of("Ayllas", "Vries", "Ayllas de Vries", true),
                Arguments.of("ayllas", "vries", "Ayllas de Vries", true),
                Arguments.of("Robert ", " Bausdorf", "Robert Bausdorf", true),
                Arguments.of("Tom", "Daalmann", "Tom Connor Daalmann", true),
                Arguments.of("John", "Doh", "John Doe", false),
                Arguments.of("John", "Do", "John Doe", false)
        );
    }
}
