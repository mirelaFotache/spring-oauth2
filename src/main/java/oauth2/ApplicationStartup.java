package oauth2;

import oauth2.user.model.Role;
import oauth2.user.model.User;
import oauth2.user.repository.UserRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class ApplicationStartup implements ApplicationListener<ApplicationReadyEvent> {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public ApplicationStartup(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {

        Optional<User> admin = userRepository.findByUsername("admin");
        if (!admin.isPresent()) {
            User userNew = new User();
            userNew.setUsername("admin");
            userNew.setPassword(passwordEncoder.encode("admin"));
            userNew.setEmail("admin@gmail.com");
            List<Role> roles = new ArrayList<Role>();
            roles.add(Role.ROLE_ADMIN);
            userNew.setRoles(roles);
            userRepository.save(userNew);
        }

        Optional<User> user = userRepository.findByUsername("user");
        if (!user.isPresent()) {
            User userNew = new User();
            userNew.setUsername("user");
            userNew.setPassword(passwordEncoder.encode("user"));
            userNew.setEmail("user@gmail.com");
            List<Role> roles = new ArrayList<Role>();
            roles.add(Role.ROLE_USER);
            userNew.setRoles(roles);
            userRepository.save(userNew);
        }
    }
}
