package com.sentinelmesh.controlplane.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public class IncomingCompromiseSignalDTO {
    @NotBlank public String hostname;
    @NotBlank public String hostIp;
    public String username;
    public String category = "unknown_compromise";
    public List<String> indicators;
}
