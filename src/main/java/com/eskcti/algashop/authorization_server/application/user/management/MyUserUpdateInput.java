package com.eskcti.algashop.authorization_server.application.user.management;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MyUserUpdateInput {

	@NotBlank
	private String name;

}
