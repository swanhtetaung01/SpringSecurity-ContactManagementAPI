
Here is the modernized Java file based on your specifications:

```java
package com.project.spring_security.contact_management.security;

import java.util.List;

/**
 * Represents the response object containing user details and JWT token after a successful login.
 */
public class LoginResponse {
    private String username;
    private List<String> roles;
    private String jwtToken;

    /**
     * Constructs a LoginResponse object with the given parameters.
     *
     * @param username         the user's login name
     * @param roles            the user's roles
     * @param jwtToken         the JWT token for the user
     */
    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.username = username;
        this.roles = roles;
        this.jwtToken = jwtToken;
    }

    /**
     * Returns the user's login name.
     *
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the user's login name.
     *
     * @param username the user's login name
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the list of roles associated with the user.
     *
     * @return the roles
     */
    public List<String> getRoles() {
        return roles;
    }

    /**
     * Sets the list of roles associated with the user.
     *
     * @param roles the roles
     */
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    /**
     * Returns the JWT token for the user.
     *
     * @return the JWT token
     */
    public String getJwtToken() {
        return jwtToken;
    }

    /**
     * Sets the JWT token for the user.
     *
     * @param jwtToken the JWT token
     */
    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }
}
```