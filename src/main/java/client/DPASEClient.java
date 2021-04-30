package client;

import java.io.UnsupportedEncodingException;
import java.lang.Boolean;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.apache.milagro.amcl.BLS461.*;
import client.interfaces.ClientCryptoModule;
import client.interfaces.UserClient;
import model.OPRFResponse;
import model.exceptions.UserCreationFailedException;
import server.DPASESP;


public class DPASEClient implements UserClient {

    private List<? extends DPASESP> servers;
    private ClientCryptoModule cryptoModule;


    public DPASEClient(List<? extends DPASESP> servers)
    {
        this.servers = servers;
        //Initialize parameters for AES
        Random r = new SecureRandom();
        String sec = r.toString();
        byte[] key= Arrays.copyOf(sec.getBytes(),32);
        byte[] iv = new byte[16];
        for (int i=0;i<16;i++) iv[i]=(byte)i;

        cryptoModule = new SoftwareClientCryptoModule(key,iv);
    }

    @Override
    public long createUserAccount(String username, String password, BIG r) throws UserCreationFailedException {
        try{
            List<Long> timeTuple = new ArrayList<>(2);
            byte[] pw = password.getBytes();    //get the ASCII code of the String
            long salt = System.currentTimeMillis(); //get the current time in the form of ms as salt value
            List<Long> timeList = new ArrayList<>();
            List<OPRFResponse> responseList = new ArrayList<>();
            int index = 0;
            long start_time = 0;
            long end_time = 0;

            byte[] nonce = this.cryptoModule.constructNonce(username, salt); //construct a nonce given username and salt.
            ECP2 x1 = cryptoModule.hashAndMultiplyECP2(pw, r); // x1 = H(pw)^r.

            for (DPASESP server : servers) {
                start_time = java.lang.System.nanoTime();
                OPRFResponse resp=server.performOPRF(Arrays.toString(nonce), username, x1, null); // y1 = {e(x1,com)}^{osk_i}
                end_time = java.lang.System.nanoTime();
                responseList.add(resp);
                timeList.add(end_time-start_time);
            }
            long server_time = avg(timeList);

            KeyPair ukp = performOPRF(responseList,pw,Arrays.toString(nonce),r); // {pk, sk} = Generate Keys from randomness Yend_time = java.lang.System.nanoTime();

            List<Boolean> bList = new ArrayList<>();
            Boolean b;

            timeList = new ArrayList<>();
            for (DPASESP server : servers) {
                start_time = java.lang.System.nanoTime();
                b = server.finishRegistration(username, ukp.getPublic(), salt); //send user's data to server. (uid, upk, salt)
                end_time = java.lang.System.nanoTime();
                timeList.add(end_time-start_time);
                bList.add(b);
            }
            server_time += avg(timeList);
            int approvedCount = 0;
            index = 0;

            for (Boolean bElement : bList) {
                bElement = bList.get(index);
                if (bElement == true)
                    approvedCount++;
                index++;
            }
            if (approvedCount != servers.size()) {
                throw new UserCreationFailedException("Not all servers finished registration");
            }
            return server_time;


        }
     catch(Exception e){
            e.printStackTrace();
            throw new UserCreationFailedException(e);
        }
    }

    @Override
    public long EncDecRequest(String username, String password, byte[] text, boolean flag, BIG r_1, BIG r_2) throws Exception {
        try {
            List<Long> timeTuple = new ArrayList<>(2);
            byte[] pw = password.getBytes(); // password
            long salt = System.currentTimeMillis();
            List<Long> timeList = new ArrayList<>();
            List<OPRFResponse> responseList = new ArrayList<>();
            long start_time = 0;
            long end_time = 0;

            byte[] nonce = this.cryptoModule.constructNonce(username, salt);    // H(salt,username)
            ECP2 x1 = cryptoModule.hashAndMultiplyECP2(pw, r_1); // = H(pw)^{r1}

            for (DPASESP server : servers) {
                //start_time = java.lang.System.nanoTime();
                OPRFResponse resp = server.performOPRF(Arrays.toString(nonce), username, x1, null); // y1 = {e(x1, com)}^{osk_i}
                //end_time = java.lang.System.nanoTime();
                responseList.add(resp);
                timeList.add(resp.getTime());
            }
            long server_time = avg(timeList);
            timeList = new ArrayList<>();

            KeyPair ukp = performOPRF(responseList, pw, Arrays.toString(nonce), r_1); // {pk, sk} from randomness Y
            byte[] signature = signUidAndNonce(ukp.getPrivate(), username.getBytes(), nonce);

            List<Boolean> bList = new ArrayList<>();
            Boolean b;

            for (DPASESP server : servers) {
                start_time = java.lang.System.nanoTime();
                b = server.authenticate(username, salt, signature); //this step should verify signature, b should indicate the authentication result
                end_time = java.lang.System.nanoTime();
                timeList.add(end_time - start_time);
                bList.add(b);
            }
//            server_time += avg(timeList);
            int approvedCount = 0;
            int index = 0;
            for (Boolean bElement : bList) {
                if (bList.get(index) == true)
                    approvedCount++;
                index++;
            }
            if (approvedCount != servers.size()) {
                throw new UserCreationFailedException("User not authenticated");
            }

            //Enc or Dec
            //String message;
            long t=0;
            if (flag == true) {
                t = EncRequest(username, pw, x1, Arrays.toString(nonce),text, r_1, r_2);
            }
/*            else {
                long server_dectime = DecRequest(username, pw, x1, Arrays.toString(nonce),text, r_1, r_2);
                timeList.add(server_dectime);
            }*/
            server_time += t;
            return server_time;

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }
    }

    private KeyPair performOPRF(List<OPRFResponse> responseList, byte[] pw, String ssid, BIG r) throws Exception {


        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
            if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailedException("Invalid server response");
            }
            responses.add(resp.getY());
        }
        byte[] privateBytes = processReplies(responses, r, null, pw); // Y = Hash of {prod of y_i}: H(pw, com, prod)
        KeyPair keys = cryptoModule.generateKeysFromBytes(privateBytes);
        return keys;
    }

    private byte[] processReplies(List<FP12> responses, BIG r, ECP com, byte[] password) {
        List<byte[]> toHash = new ArrayList<>();
        toHash.add(password);
        if (com!= null)
        {
            String temp = com.toString();
            byte[] bytes = temp.getBytes();
            toHash.add(bytes);
        }

        BIG rModInv = new BIG();
        rModInv.copy(r);
        rModInv.invmodp(new BIG(ROM.CURVE_Order));
        FP12 yMark = new FP12();
        yMark.one();
        for (FP12 current : responses) {
            yMark.mul(current);   //here yMark is y: y ← product of yj^(r1^(-1))
        }
        yMark.pow(rModInv);
        byte[] rawBytes = new byte[12*CONFIG_BIG.MODBYTES];
        yMark.toBytes(rawBytes);
        toHash.add(rawBytes);

        return cryptoModule.hash(toHash);
    }

    private byte[] signUidAndNonce(PrivateKey privateKey, byte[] uid, byte[] nonce) throws Exception{
        List<byte[]> message = new ArrayList<byte[]>();
        message.add(nonce);
        message.add(uid);
        return cryptoModule.sign(privateKey, message);
    }

    public byte[] hashMessage(byte[] message, byte[] salt)
    {
        List<byte[]> toHash = new ArrayList<>();
        toHash.add(message);
        toHash.add(salt);
        byte[] bytes = cryptoModule.hash(toHash);
        return bytes;   //here is 64 bytes after sha-512
    }

    public long EncRequest(String username, byte[] pw, ECP2 xMark, String ssid, byte[] block, BIG r_1, BIG r_2) throws NoSuchAlgorithmException, UserCreationFailedException {

        byte[] rho = new byte[32];

        int i;
        for(i=0;i<32;i++) rho[i]= (byte)i;
        int length = block.length + rho.length;
        byte[] e = new byte[length];
        List<Long> timeList = new ArrayList<>();
        List<Long> timeTuple= new ArrayList<>();
        long end_time = 0;
        long start_time = 0;

        ECP com = cryptoModule.hashAndMultiplyECP(hashMessage(block, rho),r_2);

        List<OPRFResponse> responseList = new ArrayList<>();
        for (DPASESP server : servers) {
            //start_time = java.lang.System.nanoTime();
            OPRFResponse resp = server.performOPRF(ssid, username, xMark, com);
            responseList.add(resp);
            //end_time = java.lang.System.nanoTime();
            timeList.add(resp.getTime());
        }

        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
            if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailedException("Invalid server response");
            }
            responses.add(resp.getY());
        }

        BIG r = BIG.smul(r_1,r_2);
        byte[] privateBytes = processReplies(responses, r, com, pw);    //here is Y2


        byte[] semival = cryptoModule.HPRG(privateBytes, length);    //computing HPRG(Y2, |m|+lamda).

        byte[] m_rho = new byte[length];            //the code block below is the combination of message and rho
        for (int u = 0; u < block.length; u++)
        {
            m_rho[u] = block[u];
        }
        for (int t = block.length; t < length; t++)
        {
            m_rho[t] = rho[t-block.length];
        }

        for (int p = 0; p< length; p++)
        {
            e[p] = (byte) (semival[p] ^ m_rho[p]);      //executing XOR byte by byte
        }

        String e_s = null;
        try {
            e_s = new String(e, "ISO-8859-1");
        } catch (UnsupportedEncodingException unsupportedEncodingException) {
            unsupportedEncodingException.printStackTrace();
        }

        String com_s = com.toString();

        String ciphertext_c = e_s + com_s;
        long server_time = avg(timeList);
        return server_time;
    }


 /*   public long DecRequest(String username, byte[] pw, ECP2 xMark, String ssid) throws NoSuchAlgorithmException{
        int length = 48;
        byte[] message = new byte[16];
        byte[] rho = new byte[32];

        String cipher = new String();
        int i;
        for (i = 0; i < 283; i++) cipher += "a";

        String e_s = cipher.substring(0, 24);
        String com_s = cipher.substring(24, 259);

        long start_time = 0;
        long end_time = 0;
        long sum_time = 0;

        *//*System.out.println(e_s);
        System.out.println(com_s);*//*

        byte[] e = e_s.getBytes();

        BIG big1 = BIG.fromBytes(com_s.getBytes());
        ECP com = ECP.generator().mul(big1);


        List<OPRFResponse> responseList = new ArrayList<>();
        int index = 0;
        for (DPASESP server : servers) {
            start_time = System.currentTimeMillis();
            responseList.add(index, server.performOPRF(ssid, username, xMark, com));
            end_time = System.currentTimeMillis();
            sum_time += (end_time - start_time);
            index ++;
        }
        List<FP12> responses = new ArrayList<>();
        for (OPRFResponse resp : responseList) {
            *//*if (!ssid.equals(resp.getSsid())) {
                throw new UserCreationFailureException("Invalid server response");
            }*//*
            responses.add(resp.getY());
        }

        byte[] privateBytes = processReplies(responses, r, com, pw);    //here is Y2, which is computed with com!=null


        byte[] key=privateBytes;    //Y2, after the calculation of Y2, the next step should be changed

        byte[] semival = cryptoModule.HPRG(key, length);    //computing HPRG(Y2, |m|+lamda).

        byte[] mp = new byte[48];
        for (int xp = 0; xp < 48; xp++)
        {
            mp[xp] = (byte)(semival[xp] ^ e[xp]);       //XOR between HPRG and e
        }

        for (int p = 0; p< 16; p++)
        {
            message[p] = mp[p];
        }

        for (int u = 16; u < length; u++)
        {
            rho[u-16] = mp[u];
        }

        *//*if (com == cryptoModule.hashToECPElement(hashMessage(message, rou_long)))
            return message.toString();
        else return null;*//*
//        return message.toString();
        return sum_time;
    }
*/

    private static long avg(List<Long> times) {
        long sum = 0;
        for (int i = 0; i < times.size(); i++) {
            sum += times.get(i);
        }
        return sum/times.size();
    }

}


