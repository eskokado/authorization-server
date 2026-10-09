package com.eskcti.algashop.authorization_server.application.user.management;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUserInput {

    @NotBlank
    private String name;

    @NotBlank
    @Email
    private String email;

    @NotNull
    private AuthUserType type;
}