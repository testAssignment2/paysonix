package com.test.project.paysonix.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Spy;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ReflectionUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.setField;

@SpringBootTest
class SignatureControllerTest {

    @Spy
    private SignatureController signatureControllerUnderTest;

    private final String tokenValue = "secret_token";

    @BeforeEach
    void setUp() {
        ReflectionUtils.makeAccessible(findField(SignatureController.class, "tokenValue"));
        setField(findField(SignatureController.class, "tokenValue"), signatureControllerUnderTest, tokenValue);
    }

    @Test
    void generateSignature_ValidToken_ReturnsSuccessResponse() {
        // Arrange
        Map<String, String> params = new HashMap<>();
        params.put("key1", "value1");
        params.put("key2", "value2");
        String operationId = "123";
        String token = tokenValue;
        ResponseEntity<Object> expectedResponse = ResponseEntity.ok(Map.of(
                "status", "success",
                "result", List.of(
                        Map.of("signature", "9910273191cd30829789cb76ca4a0b88c68c4f1c6f5e44882f86f9d6ece975cb")
        )));

        // Act
        ResponseEntity<Object> actualResponse = signatureControllerUnderTest.generateSignature(token, params, operationId);

        // Assert
        assertEquals(expectedResponse, actualResponse);
    }

    @Test
    void generateSignature_InvalidToken_ReturnsForbiddenResponse() {
        // Arrange
        Map<String, String> params = new HashMap<>();
        String operationId = "123";
        String token = "invalid_token";
        ResponseEntity<Object> expectedResponse = ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid Token");

        // Act
        ResponseEntity<Object> actualResponse = signatureControllerUnderTest.generateSignature(token, params, operationId);

        // Assert
        assertEquals(expectedResponse, actualResponse);
    }
}
