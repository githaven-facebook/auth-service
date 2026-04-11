package com.facebook.auth.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record TwoFactorSetupResponse(
    String secret,

    @JsonProperty("qr_code_uri")
    String qrCodeUri,

    @JsonProperty("qr_code_image")
    String qrCodeImage,

    @JsonProperty("backup_codes")
    List<String> backupCodes
) {}
