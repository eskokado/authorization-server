package com.eskcti.algashop.authorization_server.application.user.query;

import com.eskcti.algashop.authorization_server.domain.model.user.AuthUserType;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Sort;

@Data
@NoArgsConstructor
public class AuthUserFilter {

    private String email;
    private AuthUserType type;
    private int page = 0;
    private int size = 15;
    private String sort = "name";
    private Sort.Direction direction = Sort.Direction.ASC;
}
