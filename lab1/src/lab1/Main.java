package src.lab1;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Main {

    //private static String randomString = CryptoUtils.generateRandomString();
    private static final String randomString = "otNX0G2kldqUWAdrjoXrVBVNF2jk62j6Yn2p4v2NKFwnMfqygXU6-WwQNUjobeQgqzPOBIZiUDHRLuHF";

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.print("$ ./");
        while(sc.hasNextLine()){

            /*  INIT
                tajnik init masterPass
                  [0]   [1]    [2]
                PUT
                tajnik put masterPass www.fer.hr neprobojnaSifra
                  [0]   [1]    [2]     [3]           [4]
                GET
                tajnik get masterPass www.fer.hr
                  [0]   [1]    [2]     [3]
                DELETE
                tajnik delete masterPass
                  [0]   [1]    [2]
             */

            String[] instruction_splited = sc.nextLine().split(" ");

            if(!(instruction_splited.length >= 3 && instruction_splited.length <= 5)){
                System.out.println("The instruction is not valid!");
                System.out.print("$ ./");
            } else {
                switch(instruction_splited[1]){
                    case "init":
                        if(instruction_splited.length != 3) {
                            System.out.println("The instruction is not valid!");
                            continue;
                        } else {
                            init(instruction_splited[0], instruction_splited[2]);
                            break;
                        }
                    case "put":
                        if(instruction_splited.length != 5) {
                            System.out.println("The instruction is not valid!");
                            continue;
                        } else {
                            put(instruction_splited[0], instruction_splited[2], instruction_splited[3], instruction_splited[4]);
                            break;
                        }
                    case "get":
                        if(instruction_splited.length != 4) {
                            System.out.println("The instruction is not valid!");
                            continue;
                        } else {
                            get(instruction_splited[0], instruction_splited[2], instruction_splited[3]);
                            break;
                        }
                    default:
                        System.out.println("There is no such instruction!");
                }
            }
            System.out.print("$ ./");
        }

        sc.close();

    }

    private static void init(String fileName, String masterPassword) {
        //System.out.println("init");
        //System.out.println("Random string: "+ randomString);

        String path = "C:\\Users\\38595\\Desktop\\SRS\\lab1\\" + fileName + ".dat"; //using .dat to indicate that file contains raw data
        File newFile = new File(path);
        try{
            newFile.createNewFile();

            //OUTPUT: encrypted(adress, password) pair, salt, IV
            LinkedList<byte[]> outputToBeSaved = new LinkedList<>();
            byte[] salt = CryptoUtils.genSalt();
            byte[] initVector = CryptoUtils.genInitVector();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            char[] masterPasswordToBytes = masterPassword.toCharArray();
            SecretKey key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
            byte[] encryptedRandomString = CryptoUtils.encryptPassword(randomString, key, ivParameterSpec);
            outputToBeSaved.add(encryptedRandomString);
            outputToBeSaved.add(salt);
            outputToBeSaved.add(initVector);

            //save to file
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
            outputStream.writeObject(outputToBeSaved);

            //sucess
            System.out.println("Password manager initialized.");


        } catch (IOException e) {
            System.out.println("Unable to create new file");
        }

    }
    @SuppressWarnings("unchecked")
    private static void put(String fileName, String masterPassword, String address, String password) {
        //System.out.println("put");

        String path = "C:\\Users\\38595\\Desktop\\SRS\\lab1\\" + fileName + ".dat"; //using .dat to indicate that file contains raw data

        try {

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            LinkedList<byte[]> inputToBeRead;
            //read all lines to parse it later one by one
            LinkedList<LinkedList<byte[]>> readAllLines = new LinkedList<>();
            //store file lines to rewrite if afterwards
            LinkedList<LinkedList<byte[]>> fileLinesToRewrite = new LinkedList<>();

            //read first line to check masterPassword
            //INPUT: encrypted(adress, password) pair, salt, IV
            inputToBeRead = (LinkedList<byte[]>) objectInputStream.readObject();
            LinkedList<byte[]> firstLineInput = inputToBeRead;
            byte[] encryptedRandomString = inputToBeRead.get(0);
            byte[] salt = inputToBeRead.get(1);
            byte[] initVector = inputToBeRead.get(2);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            char[] masterPasswordToBytes = masterPassword.toCharArray();
            fileLinesToRewrite.add(inputToBeRead);

            SecretKey key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
            String decryptedRandomString = CryptoUtils.decryptPassword(encryptedRandomString, key, ivParameterSpec);

            //masterPasswordCheck
            if (decryptedRandomString.equals(randomString)) {
                //System.out.println("Master password correct.");

                //Is there already password for this adress? All lines must be read. Optimization using hash values? Maybe.
                //1. there is - update
                //2. there isn't - create new


                while (true) {
                    try {
                        //read next line
                        inputToBeRead = (LinkedList<byte[]>) objectInputStream.readObject();
                        readAllLines.add(inputToBeRead);
                    } catch (IOException e) {
                        //System.out.println("Reached end of file.");
                        break;
                    }
                }

                //process lines
                Boolean addressPassPairFound = false;
                LinkedList<byte[]> outputToBeSaved = new LinkedList<>();
                Map<String, String> adressPasswordMap = new HashMap<>();
                for(LinkedList<byte[]> line : readAllLines) {

                    if(line.equals(firstLineInput)) {
                        continue;
                    }

                    //try to decrypt nextLine
                    byte[] encryptedAdressPassPair = line.get(0);
                    salt = line.get(1);
                    initVector = line.get(2);
                    ivParameterSpec = new IvParameterSpec(initVector);
                    key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
                    //(adress, password)
                    String decryptedAdressPassPair = CryptoUtils.decryptPassword(encryptedAdressPassPair, key, ivParameterSpec);
                    adressPasswordMap = CryptoUtils.parseAddressPassPair(decryptedAdressPassPair);

                    //already there
                    if (adressPasswordMap.get("address").equals(address)) {
                        addressPassPairFound = true;
                        //update and add to list
                        salt = CryptoUtils.genSalt();
                        initVector = CryptoUtils.genInitVector();
                        ivParameterSpec = new IvParameterSpec(initVector);
                        key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
                        //THIS!
                        String updatedAddressPassPair = "(" + adressPasswordMap.get("address") + ", " + password + ")";
                        byte[] encryptedUpdatedAddressPassPair = CryptoUtils.encryptPassword(updatedAddressPassPair, key, ivParameterSpec);

                        outputToBeSaved.add(encryptedUpdatedAddressPassPair);
                        outputToBeSaved.add(salt);
                        outputToBeSaved.add(initVector);

                        fileLinesToRewrite.add(outputToBeSaved);


                    } else {
                        //just copy file content unchanged to list
                        outputToBeSaved = line;
                        fileLinesToRewrite.add(outputToBeSaved);

                    }

                }

                if (!addressPassPairFound) {
                    //add new pair
                    //System.out.println("Add new pair");
                    salt = CryptoUtils.genSalt();
                    initVector = CryptoUtils.genInitVector();
                    ivParameterSpec = new IvParameterSpec(initVector);
                    key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
                    //THIS!
                    String newAddressPassPair = "(" + address + ", " + password + ")";
                    byte[] encryptedNewAddressPassPair = CryptoUtils.encryptPassword(newAddressPassPair, key, ivParameterSpec);

                    outputToBeSaved.add(encryptedNewAddressPassPair);
                    outputToBeSaved.add(salt);
                    outputToBeSaved.add(initVector);

                    fileLinesToRewrite.add(outputToBeSaved);
                }

                //rewrite lines
                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(path);
                    ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);

                    for (LinkedList<byte[]> line : fileLinesToRewrite) {
                        outputStream.writeObject(line);

                    }

                    //succes
                    System.out.println("Stored password for " + address);


                } catch (IOException e) {
                    System.out.println("Error on server side!");
                }

            } else {
                System.out.println("Master password incorrect or integrity check failed.");
            }

        } catch (IOException | ClassNotFoundException| SecurityException e) {
            System.out.println("Unable to read from file");
        }

    }
    @SuppressWarnings("unchecked")
    private static void get(String fileName, String masterPassword, String address) {
        //System.out.println("get");

        String path = "C:\\Users\\38595\\Desktop\\SRS\\lab1\\" + fileName + ".dat"; //using .dat to indicate that file contains raw data

        try {

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            LinkedList<byte[]> inputToBeRead;

            //read first line to check masterPassword
            //INPUT: encrypted(adress, password) pair, salt, IV
            inputToBeRead = (LinkedList<byte[]>) objectInputStream.readObject();
            LinkedList<byte[]> firstLineInput = inputToBeRead;
            byte[] encryptedRandomString = inputToBeRead.get(0);
            byte[] salt = inputToBeRead.get(1);
            byte[] initVector = inputToBeRead.get(2);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            char[] masterPasswordToBytes = masterPassword.toCharArray();

            SecretKey key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
            String decryptedRandomString = CryptoUtils.decryptPassword(encryptedRandomString, key, ivParameterSpec);

            //masterPasswordCheck
            if(decryptedRandomString.equals(randomString)) {
                //System.out.println("Master password correct.");

                //go through file and find the matching password


                //read all lines to parse it later one by one
                LinkedList<LinkedList<byte[]>> readAllLines = new LinkedList<>();
                while (true) {
                    try {
                        //read next line
                        inputToBeRead = (LinkedList<byte[]>) objectInputStream.readObject();
                        readAllLines.add(inputToBeRead);
                    } catch (IOException e) {
                        //System.out.println("Reached end of file.");
                        break;
                    }
                }

                //process lines
                Boolean addressPassPairFound = false;
                Map<String, String> adressPasswordMap = new HashMap<>();
                for (LinkedList<byte[]> line : readAllLines) {

                    if (line.equals(firstLineInput)) {
                        continue;
                    }

                    //try to decrypt nextLine
                    byte[] encryptedAdressPassPair = line.get(0);
                    salt = line.get(1);
                    initVector = line.get(2);
                    ivParameterSpec = new IvParameterSpec(initVector);
                    key = CryptoUtils.genKey(masterPasswordToBytes, salt, 310000, 256);
                    //(adress, password)
                    String decryptedAdressPassPair = CryptoUtils.decryptPassword(encryptedAdressPassPair, key, ivParameterSpec);
                    //System.out.println("Decr: " + decryptedAdressPassPair);
                    adressPasswordMap = CryptoUtils.parseAddressPassPair(decryptedAdressPassPair);
                    //System.out.println("Address: "+ adressPasswordMap.get("address"));
                    //System.out.println("Pass: "+ adressPasswordMap.get("password"));

                    //already there
                    if (adressPasswordMap.get("address") != null && adressPasswordMap.get("address").equals(address)) {
                        addressPassPairFound = true;
                        break;
                    }

                }

                if (!addressPassPairFound) {
                    System.out.println("Master password incorrect or integrity check failed.");
                } else {
                    System.out.println("Password for " + address + " is: " + adressPasswordMap.get("password"));
                }

            } else {
                System.out.println("Master password incorrect or integrity check failed.");
            }


        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Unable to read from file");
        }



    }


    private static class CryptoUtils{
        /*
        class SecretKeyFactory - getInstance(String algorithm) - returns a SecretKeyFactory object that converts secret keys of the specified algorithm.
                               - SecretKey generateSecret(KeySpec keySpec) - generates a SecretKey object from the provided key specification (key material).
        Class PBEKeySpec - A user-chosen password that can be used with password-based encryption (PBE).
                         - The password can be viewed as some kind of raw key material, from which the encryption mechanism that uses it derives a cryptographic key.
                         - KeySpec - represents a password-based encryption key specification, converts the password characters to a PBE key by creating an instance of the appropriate secret-key factory previously
        Key class -   byte[] getEncoded() - returns the key in its primary encoding format, or null if this key does not support encoding.
        class SecretKeySpec - SecretKeySpec(byte[] key, String algorithm) - constructs a secret key from the given byte array.
         */

        private static SecretKeySpec genKey(char[] masterPassword, byte[] salt, int interationCount, int derivedKeyLength) {
            SecretKeySpec secretKeySpec = null;

            try {

                //key generation
                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec keySpec = new PBEKeySpec(masterPassword, salt, interationCount, derivedKeyLength);
                SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

                //defining key type: secret key for use with cryptographic algorithm AES
                String algorithm = "AES";
                byte[] secretKeyBytes = secretKey.getEncoded();
                secretKeySpec = new SecretKeySpec(secretKeyBytes,algorithm);

            } catch (NoSuchAlgorithmException e) {
                System.out.println("Error on server side!");
                System.exit(-1);
            } catch (InvalidKeySpecException e) {
                System.out.println("Error on server side!");
                System.exit(-1);
            }

            return secretKeySpec;
        }

        /*
        class Cipher - this class provides the functionality of a cryptographic cipher for encryption and decryption.
                     - static Cipher getInstance(String transformation)	- returns a Cipher object that implements the specified transformation.
                     - void	init(int opmode, Key key) - initializes this cipher with a key.
                     - ENCRYPT_MODE, DECRYPT_MODE
                     - byte[] doFinal(byte[] input) - encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
         */

        private static byte[] encryptPassword(String password, SecretKey key, IvParameterSpec initVector) {
            byte[] encryptedPassword = null;

            try{

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //most popular - ensured block alignment
                cipher.init(Cipher.ENCRYPT_MODE, key, initVector);
                byte[] passwordToBytes = password.getBytes();
                encryptedPassword = cipher.doFinal(passwordToBytes);

            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                System.out.println("Error on server side!");
                System.exit(-1);
            }
            return encryptedPassword;
        }

        private static String decryptPassword(byte[] encryptedPassword, SecretKey key, IvParameterSpec initVector) {
            String decryptedPassword = null;

            try{

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key, initVector);
                byte[] decryptedPasswordBytes = cipher.doFinal(encryptedPassword);
                decryptedPassword = new String(decryptedPasswordBytes, "UTF-8");

            } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                //System.out.println("Error on server side!");
                return "";
            }

            return decryptedPassword;
        }

        /*
        SecureRandom class provides a cryptographically strong random number generator (RNG).
        Typical callers of SecureRandom invoke the following methods to retrieve random bytes:

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);

         */
        private static byte [] genSalt() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            return salt;

        }
        public static byte[] genInitVector() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] initVector = new byte[16];
            secureRandom.nextBytes(initVector);
            return initVector;
        }

        private static String generateRandomString() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] bytes = new byte[80];
            secureRandom.nextBytes(bytes);
            String randomString = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).substring(0, 80);
            return randomString;
        }

        private static Map<String, String> parseAddressPassPair(String input) {
            // Remove parentheses and split the string by comma
            String[] parts = input.substring(1, input.length() - 1).split(",");

            // Trim whitespace from the address and password strings
            String address = parts[0].trim();
            String password = parts[1].trim();

            // Create a map to store the address and password
            Map<String, String> addressPasswordMap = new HashMap<>();
            addressPasswordMap.put("address", address);
            addressPasswordMap.put("password", password);

            return addressPasswordMap;
        }
    }


}
