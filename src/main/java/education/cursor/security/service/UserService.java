package education.cursor.security.service;

import education.cursor.security.entity.User;

public interface UserService {

  User getByUsername(String username);
  User create(User user);
}
