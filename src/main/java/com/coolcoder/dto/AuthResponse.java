package com.coolcoder.dto;

import com.coolcoder.model.User;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String message;
    private User user;
}
