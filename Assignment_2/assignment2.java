import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.*;

public class assignment2 implements Assignment2Interface {
    public static void main(String[] args ) throws IOException, NoSuchAlgorithmException {

        assignment2 signature = new assignment2();

        BigInteger primeModulus = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        
        BigInteger generatorKey = new BigInteger("1010101010101010", 16);
        
        BigInteger privateKeyX = new BigInteger("92ca96f0b45ac7ea0d91d41b3b466fa354f541ffce4e81cd2b4718fb2b7d2810256727f78a8ca23a2c18b60965ae905d9cdb2eb9f693890dd94c7ba346740a29847f4c8cbbd61a6cbabb1315877dd03603265e896eb0dea6dcfc57bbafaf73b9fe2bc4b9241096f4d495641ec97cf4b7bcad1a6d4ba77703046229c457602fa3", 16);

        BigInteger k = new BigInteger("1151008269", 10);

        String filename = args[0];      // read in class file as an argument
        Path filepath = Paths.get(filename);
        byte [] fileBytes = Files.readAllBytes(filepath);
        byte [] hashedBytes = signature.hashSHA256(fileBytes);

        BigInteger [] allKeys = signature.getAllValues(generatorKey, privateKeyX, k, primeModulus, hashedBytes);

        String y = allKeys[0].toString(16);  // public key
        String r = allKeys[1].toString(16);
        String s = allKeys[2].toString(16);

        FileWriter writeFileR = new FileWriter("r.txt");
        FileWriter writerFileS = new FileWriter("s.txt");
        FileWriter writerFileY = new FileWriter("y.txt");

        BufferedWriter bufferWriteR = new BufferedWriter(writeFileR);
        BufferedWriter bufferWriteS = new BufferedWriter(writerFileS);
        BufferedWriter bufferWriteY = new BufferedWriter(writerFileY);

        bufferWriteR.write(r);
        bufferWriteS.write(s);
        bufferWriteY.write(y);

        bufferWriteR.close();
        bufferWriteS.close();
        bufferWriteY.close();

        System.out.println("Public Key (y):" + "\n" + y.toString(16));
        System.out.println("----------------------");
        System.out.println();
        System.out.println("Value of r:" + "\n" + r.toString(16));
        System.out.println("----------------------");
        System.out.println();
        System.out.println("Value of s:" + "\n" + s.toString(16));
        System.out.println("----------------------");
        System.out.println();

        String res = signature.verifySignature(hashedBytes, generatorKey, r, s, y, primeModulus);
        System.out.println("Check if v1 = v2: " + res);
        
        // checks if values are within given range
        // String rangeRes = signature.checkRange(r, primeModulus);
        // System.out.println(rangeRes);

    }

    public BigInteger [] getAllValues(BigInteger g, BigInteger x, BigInteger k, BigInteger primeMod, byte [] hashedFile) {

        BigInteger pModDec = primeMod.subtract(BigInteger.ONE);     // primeModulus minus 1
        BigInteger y = generateY(g, x, primeMod);
        BigInteger r = generateR(g, k, primeMod);
        BigInteger s = generateS(hashedFile, x, r, k, pModDec);

        while(s.equals(BigInteger.ZERO)){                           // checks if s == 0
            s = generateS(hashedFile, x, r, k, pModDec);
        }

        return new BigInteger [] {y, r, s};
    }

    // https://www.freecodecamp.org/news/euclidian-gcd-algorithm-greatest-common-divisor/
    @Override
    public BigInteger calculateGCD(BigInteger a, BigInteger b) {
        if(b == BigInteger.ZERO) {
            return a;
        }
        return calculateGCD(b, a.mod(b));
    }
    
    @Override
    public BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus) {
        // public key
        // generate y = g^x mod(p)
        BigInteger y = generator.modPow(secretKey, modulus);
        return y;
    }

    @Override
    public BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus) {
        // compute r as r = g^k (mod p)
        BigInteger r = generator.modPow(k, modulus);
        return r;
    }

    @Override
    public BigInteger generateS(byte [] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus) {
        // compute s as s = (H(m)-xr)k^-1 (mod p-1)
        // m = plaintext (hashed class file)
        // x = secretKey (private key)
        // the modulus being passed has been decreased by 1

        BigInteger hashedFile = new BigInteger(plaintext);
        // splitting into 3 parts
        BigInteger hashedMinusXR = (hashedFile.subtract(secretKey.multiply(r))).mod(modulus);   // (H(m)-xr) (mod p-1)
        BigInteger inverseK = calculateInverse(k, modulus);                                     // k^-1 (mod p-1)
        BigInteger s = (hashedMinusXR.multiply(inverseK)).mod(modulus);                         // multiply a and b together (mod p-1)

        return s;
    }

    // https://stackoverflow.com/questions/39437988/java-modular-multiplicative-inverse
    // https://algorithmist.com/wiki/Modular_inverse
    @Override
    public BigInteger calculateInverse(BigInteger a, BigInteger b) {

        BigInteger [] checkInverse = calculateXGCD(a, b);

        if (!checkInverse[0].equals(BigInteger.ONE)) {
            System.out.println("no inverse!");
            return BigInteger.ZERO;
        } else {
            return checkInverse[1].mod(b);
        }
    }

    // https://stackoverflow.com/questions/39437988/java-modular-multiplicative-inverse
    // https://algorithmist.com/wiki/Modular_inverse
    public BigInteger [] calculateXGCD(BigInteger a, BigInteger b){
        // ax + by = gcd
        // Base Case
        if (b == BigInteger.ZERO) {
            return new BigInteger [] { a, BigInteger.ONE, BigInteger.ZERO };    // b = quotient, c = remainder
        }
        // values array contains the gcd and coefficients to a and b
        BigInteger [] values = calculateXGCD(b, a.mod(b));
        BigInteger gcd = values[0];
        BigInteger x = values[2];                          
        BigInteger y = values[1].subtract((a.divide(b)).multiply(values[2]));
        
        return new BigInteger [] { gcd, x, y };
    }

    // from first assignment with a little bit of tweaking
    public byte [] hashSHA256(byte [] key) throws NoSuchAlgorithmException {
        MessageDigest mD = MessageDigest.getInstance("SHA-256");
        byte [] hashedKey = mD.digest(key);
        return hashedKey;
    }

    // checks if the values are within the given range
    // for debugging purposes
    // check that 0 < r < p and 0 < s < p-1
    public String checkRange(BigInteger s, BigInteger modulus){
        // s should be range 1 to p-2
        // y should be range 1 to p-1
        // r should be range 1 to p-1
        // x should be range 2 to p-2
        // change the values to the appropriate value to be checked

        // compareTo()
        // 0: equal
        // 1: value is greater than the passed param
        // -1: value is less than the passed param

        if(s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(modulus.subtract(BigInteger.valueOf(2))) == -1) {
            return "Within range";
        } else {
            return "Outside range";
        }
    }

    // verify if v1 = v2
    public String verifySignature(byte [] digest, BigInteger g, BigInteger r, BigInteger s, BigInteger y, BigInteger mod){
        // v1 = g^h(m) mod p
        // v2 = y^r r^s mod p
        // modPow(exponent, modulus)

        BigInteger hashedFile = new BigInteger(digest);
        BigInteger v1 = g.modPow(hashedFile, mod);

        BigInteger a1 = y.modPow(r, mod);
        BigInteger a2 = r.modPow(s, mod);
        BigInteger v2 = (a1.multiply(a2)).mod(mod);

        if (v1.compareTo(v2) == 0){
            // System.out.println(v1);
            // System.out.println(v2);
            return "Verified equal";
        } else {
            return "Not equal";
        }
    }
}
