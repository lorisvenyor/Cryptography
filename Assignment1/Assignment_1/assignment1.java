import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class assignment1 implements Assignment1Interface {
    public static void main(String[] args) throws IOException {

        assignment1 cipher = new assignment1();

        // hex strings (1 hex = 4 bits therefore, 32 x 4 = 128 bits)
        String password = "5qJgNjS^uB7Rme*=";

        Path IVtxt = Paths.get("IV.txt");
        String IV = Files.readString(IVtxt);

        Path saltTxt = Paths.get("Salt.txt");
        String salt = Files.readString(saltTxt);

        BigInteger exponent = new BigInteger("65537");
        BigInteger publicModulus = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);

        String filename = args[0];
        Path filepath = Paths.get(filename);
        byte[] fileBytes = Files.readAllBytes(filepath);

        byte[] passwordBytes = passwordUTF8(password);
        byte[] saltBytes = convertHexToByte(salt);
        byte[] ivBytes = convertHexToByte(IV);

        byte[] hashedKey = cipher.generateKey(passwordBytes, saltBytes);

        byte[] encryptedText = cipher.encryptAES(fileBytes, ivBytes, hashedKey);
        System.out.println(convertByteToHex(encryptedText));

        // FOR DECRYPTING PURPOSES
        // byte[] decryptedText = cipher.decryptAES(encryptedText, ivBytes, hashedKey);
        // System.out.println(convertByteToHex(decryptedText));

        byte[] encryptedPassword = cipher.encryptRSA(passwordBytes, exponent, publicModulus);
        String encryptedPasswordToHex = convertByteToHex(encryptedPassword);
        // write the encrypted text to Password.txt
        FileWriter writeEncryptedText = new FileWriter("Password.txt");
        writeEncryptedText.write(encryptedPasswordToHex);
        writeEncryptedText.close();
    }

    // password string to bytes UTF-8
    public static byte[] passwordUTF8(String password) throws UnsupportedEncodingException
    {
        byte[] passwordBytes = password.getBytes("UTF-8");
        return passwordBytes;
    }

    // reference:  https://www.geeksforgeeks.org/java-program-to-convert-hex-string-to-byte-array/
    public static byte[] convertHexToByte(String string) {
        
        byte[] hexToByteArray = new byte[string.length() / 2];     // 32 divided by 2 = 16 bytes array
    
        for (int i = 0; i < hexToByteArray.length; i++) {
            int index = i * 2;      // 2 hex digits = 1 byte
           
            int intValue = Integer.parseInt(string.substring(index, index + 2), 16);        // convert string to int base 16
            hexToByteArray[i] = (byte) intValue;
        }
        return hexToByteArray;
    }

    // reference: https://www.programiz.com/java-programming/examples/convert-byte-array-hexadecimal
    public static String convertByteToHex(byte[] byteArray)
    {
        String byteToHex = "";
  
        for (byte x : byteArray) {
            byteToHex = byteToHex + String.format("%02X", x);
        }
        return byteToHex;
    }

    public static byte[] deletePadding(byte[] decryptedText){

        int paddingSize = 0;
        int i = decryptedText.length - 1;

        while (decryptedText[i] == (byte) 0) {      // starting at the end of the text, we increment the paddingSize by 1 until we dont get a zero bit
            paddingSize++;
            i--;
        }

        paddingSize += 1;   // add one for the 128 bit

        int plainTextLen = decryptedText.length - paddingSize;

        byte[] plainText = new byte[plainTextLen];
        System.arraycopy(decryptedText, 0, plainText, 0, plainTextLen);

        return plainText;
    }

    // reference: https://tutorialspoint.dev/language/java/sha-256-hash-in-java
    public static byte[] hashSHA256(byte[] key){
        try { 
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < 200; i++){
                key = md.digest(key); 
            }
            return key;
        }
        catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
            return null; 
        } 
    }

    // reference: https://www.tutorialspoint.com/java/lang/system_arraycopy.htm
    @Override
    public byte[] generateKey(byte[] password, byte[] salt) {
        
        byte[] keyByteArray = new byte[password.length + salt.length];
        System.arraycopy(password, 0, keyByteArray, 0, password.length);
        System.arraycopy(salt, 0, keyByteArray, password.length, salt.length);

        return hashSHA256(keyByteArray);
    }

    // reference: https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
    @Override
    public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) {
        try {

            IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");

            Cipher encryption = Cipher.getInstance("AES/CBC/NoPadding");
            encryption.init(Cipher.ENCRYPT_MODE, AESkey, ivParamSpec);

            // n = block size, k = last part of the plaintext bit
            // Append 1 followed by n - k - 1 0-bits. If k = n, then create an extra block starting with 1 followed by n-1 0-bits.

            int paddingSize = 16 - (plaintext.length % 16);     // plaintext.length % 16, to get the length of the last block of plaintext

            byte[] paddedFile = new byte[plaintext.length + paddingSize];      // the length of the padded file
            
            System.arraycopy(plaintext, 0, paddedFile, 0, plaintext.length);       // copies plaintext to paddedfile

		    paddedFile[plaintext.length] = (byte) 128;      // add 128 bits   

		    for (int i = plaintext.length + 1; i < paddedFile.length; i++) 
            {
			    paddedFile[i] = (byte) 0;
		    }
    
            byte[] encryptedBytes = encryption.doFinal(paddedFile);
            
            return encryptedBytes;

        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
            return null;
        }
    }

    // reference: https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
    @Override
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) {
        try {

            IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");

            Cipher decryption = Cipher.getInstance("AES/CBC/NoPadding");
            decryption.init(Cipher.DECRYPT_MODE, AESkey, ivParamSpec);

            byte[] decryptedBytes = decryption.doFinal(ciphertext);

            byte[] plainText = deletePadding(decryptedBytes);       // remove padding
            
            return plainText;

        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
            return null;
        }
    }

    @Override
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) {

        BigInteger base = new BigInteger(plaintext);
        BigInteger modExpRes = modExp(base, exponent, modulus);
        byte[] encryptedPasswordRSA = modExpRes.toByteArray();      // convert big integer to byte array
        
        // to verify result from modExp is the same as modPow
        // BigInteger fromModPowResult = base.modPow(exponent, modulus);
        // byte[] modPowResult = fromModPowResult.toByteArray();
        // System.out.println(Arrays.equals(encryptedPasswordRSA, modPowResult));      

        return encryptedPasswordRSA;
    }

    @Override
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
       
        // square and multiply algorithm from notes right to left variant
        // y = a^x (mod n) where a is base
        // y = 1
        // for i = 0 to k-1 do 
	    //     if xi = 1 then y = (y*a) mod n end if
	    //     a = (a*a) mod n
        // end for

        // base here is the BigInterger(plaintext)
        String exponentBytes = exponent.toString(2);    // converting exponent into binary as written in the notes
        BigInteger y = BigInteger.ONE;                  // set y to BigInteger.ONE since modulus and base are of BigInteger type 

        // for loop following the notes
        for(int i = 0; i < exponentBytes.length(); i++){
            if(exponentBytes.charAt(i) == '1'){
                y = (y.multiply(base)).mod(modulus);
            }
            base = (base.multiply(base)).mod(modulus);
        }
        return y;
    }
}
