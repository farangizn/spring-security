package org.example.oauth.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class SecurityRunner implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Value("spring.jpa.hibernate.ddl-auto")
    private String ddl;
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        if (ddl.equals("create")) {
            Role roleUser = roleRepository.save(new Role(1, RoleName.ROLE_USER));
            Role roleAdmin = roleRepository.save(new Role(2, RoleName.ROLE_ADMIN));
            roleRepository.save(roleUser);
            roleRepository.save(roleAdmin);
            userRepository.saveAll(List.of(
                    new User(null, "admin", passwordEncoder.encode("root123"),
                            List.of(roleAdmin)),
                    new User(null, "user", passwordEncoder.encode("root123"),
                            List.of(roleUser)
                    )
            ));
        }
    }



}
