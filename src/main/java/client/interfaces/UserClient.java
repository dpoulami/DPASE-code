package client.interfaces;

import model.exceptions.UserCreationFailedException;
import org.apache.milagro.amcl.BLS461.BIG;

import java.util.List;

public interface UserClient {

    public long createUserAccount(String username, String password, BIG r) throws UserCreationFailedException;

    public long EncDecRequest(String username, String password, byte[] text, boolean flag, BIG r_1, BIG r_2) throws Exception;

}