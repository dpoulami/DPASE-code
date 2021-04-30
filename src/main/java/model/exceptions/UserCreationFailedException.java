package model.exceptions;

public class UserCreationFailedException extends Exception{
    public UserCreationFailedException() {
        }

        public UserCreationFailedException(Exception e) {
            super(e);
        }

        public UserCreationFailedException(String string) {
            super(string);
        }

    }

