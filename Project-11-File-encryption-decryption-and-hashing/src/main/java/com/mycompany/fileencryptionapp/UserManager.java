package com.mycompany.fileencryptionapp;

import java.util.ArrayList;
import java.util.List;

public class UserManager {
    private List<User> users;

    public UserManager() {
        users = new ArrayList<>();
    }

    public boolean registerUser(String username, String password) {
        // Check if the username already exists
        for (User user : users) {
            if (user.getUsername().equals(username)) {
                return false; // Username already taken
            }
        }

        // Register the new user
        User newUser = new User(username, password);
        users.add(newUser);
        return true;
    }

    public boolean authenticateUser(String username, String password) {
        // Check if the username and password match
        for (User user : users) {
            if (user.getUsername().equals(username) && user.getPassword().equals(password)) {
                return true; // Authentication successful
            }
        }

        return false; // Authentication failed
    }
}
