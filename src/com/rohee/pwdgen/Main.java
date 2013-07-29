package com.rohee.pwdgen;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {

    public static void main(String[] args) {

        double d = 4 * Math.log(300000) / Math.log(2);

        try {
            SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");

            for(int i = 0; i < 100; i++)
                System.out.println(PwdGen.generatePassword(12, rnd));
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e);
            System.exit(10);
        }
    }
}
