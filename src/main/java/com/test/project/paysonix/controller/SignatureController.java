package com.test.project.paysonix.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class SignatureController {

    @Value("${token.value}")
    private String tokenValue;

    /**
     * Generate signature from request params
     *
     * @param token secret token
     * @param params parameters
     * @param operationId operation id
     * @return signature value
     */
    @PostMapping("/api/signature/{operationId}")
    public ResponseEntity<Object> generateSignature(
            @RequestHeader(value = "Token") String token,
            @RequestBody Map<String, String> params,
            @RequestParam(value = "operationId") String operationId
    ) {
        if (!token.equals(tokenValue)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid Token");
        }

        String paramString = constructParametersString(params);
        String signature = generateHmacSha256(paramString);
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "result", List.of(Map.of("signature", signature))
        ));
    }

    /**
     * Convert params with template
     *
     * @param params request params
     * @return request params as one string
     */
    private String constructParametersString(Map<String, String> params) {
        List<String> paramNames = new ArrayList<>(params.keySet());
        Collections.sort(paramNames);

        StringBuilder paramStrBuilder = new StringBuilder();
        for (String paramName : paramNames) {
            if (paramStrBuilder.length() > 0) {
                paramStrBuilder.append("&");
            }
            paramStrBuilder.append(paramName).append("=").append(params.get(paramName));
        }
        return paramStrBuilder.toString();
    }

    /**
     * Generate HMAC SHA256 hash
     *
     * @param data params of the request
     * @return HMAC SHA256 hash
     */
    private String generateHmacSha256(String data) {
        try {
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(tokenValue.getBytes(), "HmacSHA256");
            sha256Hmac.init(secretKey);
            byte[] hmacData = sha256Hmac.doFinal(data.getBytes());
            return bytesToHex(hmacData);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Convert bytes to hex
     *
     * @param bytes byte value
     * @return hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
