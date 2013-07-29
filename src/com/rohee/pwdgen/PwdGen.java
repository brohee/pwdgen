package com.rohee.pwdgen;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Generate a somewhat pronouncable password.
 */
public abstract class PwdGen {

    private static double log2(int number) {
        // we only call it on integers in practice
        return Math.log(number) / Math.log(2);
    }
    /**
     * Generates a password with a minimum length of 14 characters.
     *
     * A minimum entropy of 32 bits (conservatively counted) is also ensured.
     */
    public static String generatePassword() {
        return generatePassword(14);
    }

    /**
     * Generates a password at least <code>minLength</code> characters long.
     * It uses a cryptographically strong random number generator as its source of entropy.
     *
     * A minimum entropy of 32 bits (conservatively counted) is also ensured.
     *
     * @param minLength Minimal length of the created password.
     * @return  A randomly generated password.
     */
    public static String generatePassword(int minLength) {
        try {
            SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
            return generatePassword(minLength, rnd);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); // something very wrong with the JRE if it happens
        }
    }

    /**
     * Generates a password at least <code>minLength</code> characters long.
     * It uses the <code>rnd</code> random number generator as its source of entropy.
     *
     * A minimum entropy of 32 bits (conservatively counted) is also ensured (only if rnd is a cryptographically
     * strong RNG).
     */
    public static String generatePassword(int minLength, Random rnd) {
        StringBuilder buf = new StringBuilder(minLength + 10);
        double entropy = 0;

        while (buf.length() < minLength || entropy < 32) {
            int choice = rnd.nextInt(100);
            final double choiceEntropy = log2(3); // lower bound, as each choice is not equiprobable
            entropy += choiceEntropy; // not sure of that estimate

            if (choice > 80) { // 20% chance of non alphanumeric char
                final char NON_ALPHA[] = {'!', '.', '%', ',', '-', '+', '*', '_', '/', '\\', '$', '#', '~' };
                buf.append(NON_ALPHA[rnd.nextInt(NON_ALPHA.length)]);

                final double NON_ALPHA_ENTROPY =  log2(NON_ALPHA.length);
                entropy += NON_ALPHA_ENTROPY;

                continue;
            }

            if (choice > 50) { // 30% chance of digit
                buf.append(rnd.nextInt(10));

                final double log10 = log2(10);
                entropy += log10;
                continue;
            }

            // 50% chance of pronouncable phoneme
            entropy += appendPhoneme(buf, rnd);
        }

        System.out.print("entropy: " + Math.floor(entropy) + " length: " + buf.length() + " ");

        return buf.toString();
    }

    /**
     * Appends a phoneme to buf, returns its entropy.
     *
     * @param buf The buffer we append a phoneme to.
     * @param rnd A random number generator, should be a secure one except in the context of unit testing.
     * @return The entropy of the phoneme we just created.
     */
    private static double appendPhoneme(StringBuilder buf,
                                        Random rnd) {
        final String FIRST_PART[] = {"B", "Bl", "Br", "Bz", "C", "Ch", "Ch", "D", "Dj" /* the D is silent */, "Dr",
                                     "F", "G", "Gl", "Gr", "H", "J", "K", "Kh", "Kl", "Kr", "L", "Ll", "M", "Mn",
                                     "N", "P", "Pl", "Pr", "Q", "R", "S", "Ss",
                                     "T", "Tch", "Ts", "V", "Vr", "W", "X",
                                     "Z", "Zd"};

        final String SECOND_PART[] = {"a", "aa", "am", "an",
                                      "e", "ee", "eel", "eek", "eem", "een", "ei",
                                      "i", "ia", "ie", "im", "in", "io", "iom", "ion", "iot", "it", "iv", "iw", "ix",
                                      "o", "ol", "om", "on", "oo", "ool", "oom", "oon", "oor", "oot",
                                      "or", "ot", "ou", "ov", "ow", "ox",
                                      "u", "um", "un",
                                      "y", "ym", "yn"};

        buf.append(FIRST_PART[rnd.nextInt(FIRST_PART.length)]);
        buf.append(SECOND_PART[rnd.nextInt(SECOND_PART.length)]);

        return log2(FIRST_PART.length) + log2(SECOND_PART.length);
    }
}
