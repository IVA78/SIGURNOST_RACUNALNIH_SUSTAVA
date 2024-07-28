package src.lab2;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class PasswordsAuth {

    public static void main(String[] args) {

        //file init
        String fileName = "passwords";
        String path = "C:\\Users\\38595\\Desktop\\SRS\\lab2\\" + fileName + ".txt";
        File file = new File(path);

        try {
            if (!file.exists()) {
                // Create a new file
                if (file.createNewFile()) {
                    //System.out.println("File created successfully.");
                } else {
                    //System.out.println("Failed to create the file.");
                }
            } else {
                //System.out.println("File already exists.");
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }

        //read from command line
        Scanner sc = new Scanner(System.in);
        System.out.print("$./");
        while(sc.hasNextLine()){
            //usermgmt add sgros
            //program operation username

            //login sgros
            //program username

            String[] instruction_splited = sc.nextLine().split(" ");
            if(instruction_splited.length > 3) {
                System.out.println("The instruction is not valid!1");
                System.out.print("$ ./");
            } else {
                if (instruction_splited.length == 3) {
                    //admin
                    if(instruction_splited[0].equals("usermgmt")) {
                        switch (instruction_splited[1]){
                            case "add":
                                //send username
                                add(instruction_splited[2], path);
                                break;
                            case "passwd":
                                passwd(instruction_splited[2], path);
                                break;
                            case "forcepass":
                                forcepass(instruction_splited[2], path);
                                break;
                            case "del":
                                del(instruction_splited[2], path);
                                break;
                            default:
                                System.out.println("The instruction is not valid!2");
                                break;
                        }
                    } else {
                        System.out.println("The instruction is not valid!3");
                        System.out.print("$./");
                    }
                } else if (instruction_splited.length == 2) {
                    //user
                    if(instruction_splited[0].equals("login")) {
                        login(instruction_splited[1], path);
                    } else {
                        System.out.println("The instruction is not valid!4");
                        System.out.print("$./");
                    }
                } else {
                    System.out.println("There is no such instruction!");
                }

                System.out.print("$./");
            }
        }
        sc.close();
    }
    @SuppressWarnings("unchecked")
    private static void add(String username, String path) {
        LinkedList<Map<String, List<String>>> fileLinesToRewrite = new LinkedList<>();
        //check if user already exists
        boolean userExists = false;
        try{

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            Map<String, List<String>> inputToBeRead = new HashMap<>();

            LinkedList<Map<String, List<String>>> readAllLines = new LinkedList<>();

            while (true) {
                try {
                    //read next line
                    inputToBeRead = (Map<String, List<String>>) objectInputStream.readObject();
                    readAllLines.add(inputToBeRead);
                } catch (IOException | ClassNotFoundException e) {
                    //System.out.println("Reached end of file.");
                    break;
                }
            }

            for(Map<String, List<String>> map : readAllLines) {

                for(Map.Entry<String, List<String>> entry : map.entrySet()){
                    String key = entry.getKey(); // Get the key
                    List<String> values = entry.getValue();

                    if(Arrays.equals(username.toCharArray(), key.toCharArray())) {
                        userExists = true;
                    }

                    fileLinesToRewrite.add(map);
                }
            }

        } catch (IOException e) {
            System.out.println("Failed to open file!");
            return;
        }

        if(userExists){
            System.out.println("This user already exists in file!");
            return;
        }


        char[] password1 = System.console().readPassword("Password:");
        char[] password2 = null;
        //check password1
        if(AuthUtils.checkPasswordConstr(password1)) {
            password2 = System.console().readPassword("Repeat Password:");
        } else {
            return;
        }

        //check pass1 and pass2 matching
        if (!Arrays.equals(password1, password2)) {
            System.out.println("User add failed. Password mismatch.");
        } else {
            Map<String, List<String>> outputToBeSaved = new HashMap<>();

            //hash password
            byte[] salt = AuthUtils.genSalt();
            String hashPassStr = AuthUtils.hashPassword(password2, salt);

            //store username, password, salt and forcepass in file
            String key = username;
            List<String> values = new ArrayList<>();
            values.add(hashPassStr);
            values.add(Base64.getEncoder().encodeToString(salt));
            values.add("no");
            outputToBeSaved.put(key, values);
            fileLinesToRewrite.add(outputToBeSaved);

            try {
                FileOutputStream fileOutputStream = new FileOutputStream(path);
                ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
                for (Map<String, List<String>> line : fileLinesToRewrite) {
                    outputStream.writeObject(line);
                }
            } catch (IOException e) {
                System.out.println("Error on server side!");
            }

            System.out.println("User " + username + " successfuly added.");
        }

    }

    @SuppressWarnings("unchecked")
    private static void passwd(String username, String path) {

        LinkedList<Map<String, List<String>>> fileLinesToRewrite = new LinkedList<>();

        //check if user exists
        boolean userExists = false;
        String oldPassword = null;
        byte[] oldSalt = null;
        String oldForcepass = null;
        try{

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            Map<String, List<String>> inputToBeRead = new HashMap<>();

            LinkedList<Map<String, List<String>>> readAllLines = new LinkedList<>();

            while (true) {
                try {
                    //read next line
                    inputToBeRead = (Map<String, List<String>>) objectInputStream.readObject();
                    readAllLines.add(inputToBeRead);
                } catch (IOException | ClassNotFoundException e) {
                    //System.out.println("Reached end of file.");
                    break;
                }
            }

            for(Map<String, List<String>> map : readAllLines) {
                for(Map.Entry<String, List<String>> entry : map.entrySet()){
                    String key = entry.getKey(); // Get the key
                    List<String> values = entry.getValue();

                    if(Arrays.equals(username.toCharArray(), key.toCharArray())) {
                        //System.out.println("This user already exists in file!");
                        userExists = true;

                        oldPassword = values.get(0);
                        String salt = values.get(1);
                        oldSalt = Base64.getDecoder().decode(salt);
                        oldForcepass = values.get(2);

                    } else {
                        fileLinesToRewrite.add(map);
                    }
                }
            }

        } catch (IOException e) {
            System.out.println("Failed to open file!");
            return;
        }

        if(!userExists){
            System.out.println("This user does not exist!");
            return;
        }

        //update password
        char[] password1 = System.console().readPassword("Password:");
        char[] password2 = null;

        //check password1 - repeating
        String newPassHash = AuthUtils.hashPassword(password1, oldSalt);
        if(Arrays.equals(newPassHash.toCharArray(), oldPassword.toCharArray())) {
            System.out.println("New pasword is the same as the old one!");
            return;
        }

        //check password1 - constraints
        if(AuthUtils.checkPasswordConstr(password1)) {
            password2 = System.console().readPassword("Repeat Password:");
        } else {
            return;
        }

        //check pass1 and pass2 matching
        if (!Arrays.equals(password1, password2)) {
            System.out.println("User add failed. Password mismatch.");
        } else {

            Map<String, List<String>> outputToBeSaved = new HashMap<>();

            //hash password
            byte[] salt = AuthUtils.genSalt();
            String hashPassStr = AuthUtils.hashPassword(password2, salt);

            //store username, password, salt and forcepass in file
            String key = username;
            List<String> values = new ArrayList<>();
            values.add(hashPassStr);
            values.add(Base64.getEncoder().encodeToString(salt));
            values.add(oldForcepass);
            outputToBeSaved.put(key, values);
            fileLinesToRewrite.add(outputToBeSaved);

            try {
                FileOutputStream fileOutputStream = new FileOutputStream(path);
                ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
                for (Map<String, List<String>> line : fileLinesToRewrite) {
                    outputStream.writeObject(line);
                }
            } catch (IOException e) {
                System.out.println("Error on server side!");
            }
            System.out.println("Password change successful.");
        }

    }
    @SuppressWarnings("unchecked")
    private static void forcepass(String username, String path) {

        LinkedList<Map<String, List<String>>> fileLinesToRewrite = new LinkedList<>();

        //check if user exists
        boolean userExists = false;
        String oldPassword = null;
        byte[] oldSalt = null;
        String oldForcepass = null;
        try{

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            Map<String, List<String>> inputToBeRead = new HashMap<>();

            LinkedList<Map<String, List<String>>> readAllLines = new LinkedList<>();

            while (true) {
                try {
                    //read next line
                    inputToBeRead = (Map<String, List<String>>) objectInputStream.readObject();
                    readAllLines.add(inputToBeRead);
                } catch (IOException | ClassNotFoundException e) {
                    //System.out.println("Reached end of file.");
                    break;
                }
            }

            for(Map<String, List<String>> map : readAllLines) {
                for(Map.Entry<String, List<String>> entry : map.entrySet()){
                    String key = entry.getKey(); // Get the key
                    List<String> values = entry.getValue();

                    if(Arrays.equals(username.toCharArray(), key.toCharArray())) {
                        //System.out.println("This user already exists in file!");
                        userExists = true;

                        oldPassword = values.get(0);
                        String salt = values.get(1);
                        oldSalt = Base64.getDecoder().decode(salt);
                        oldForcepass = values.get(2);

                    } else {
                        fileLinesToRewrite.add(map);
                    }
                }
            }

        } catch (IOException e) {
            System.out.println("Failed to open file!");
            return;
        }

        if(!userExists){
            System.out.println("This user does not exist!");
            return;
        }

        Map<String, List<String>> outputToBeSaved = new HashMap<>();

        //store username, password, salt and UPDATED forcepass in file
        String key = username;
        List<String> values = new ArrayList<>();
        values.add(oldPassword);
        values.add(Base64.getEncoder().encodeToString(oldSalt));
        values.add("yes");
        outputToBeSaved.put(key, values);
        fileLinesToRewrite.add(outputToBeSaved);

        //System.out.println("Old forcepass: "+ oldForcepass);
        //System.out.println("New forcepass: "+ values.get(2));

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
            for (Map<String, List<String>> line : fileLinesToRewrite) {
                outputStream.writeObject(line);
            }
        } catch (IOException e) {
            System.out.println("Error on server side!");
        }
        System.out.println("User will be requested to change password on next login.");

    }
    @SuppressWarnings("unchecked")
    private static void del(String username, String path) {

        LinkedList<Map<String, List<String>>> fileLinesToRewrite = new LinkedList<>();

        //check if user exists
        boolean userExists = false;
        try{

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            Map<String, List<String>> inputToBeRead = new HashMap<>();

            LinkedList<Map<String, List<String>>> readAllLines = new LinkedList<>();

            while (true) {
                try {
                    //read next line
                    inputToBeRead = (Map<String, List<String>>) objectInputStream.readObject();
                    readAllLines.add(inputToBeRead);
                } catch (IOException | ClassNotFoundException e) {
                    //System.out.println("Reached end of file.");
                    break;
                }
            }

            for(Map<String, List<String>> map : readAllLines) {
                for(Map.Entry<String, List<String>> entry : map.entrySet()){
                    String key = entry.getKey(); // Get the key
                    List<String> values = entry.getValue();

                    if(Arrays.equals(username.toCharArray(), key.toCharArray())) {
                        //System.out.println("This user already exists in file!");
                        userExists = true;

                    } else {
                        fileLinesToRewrite.add(map);
                    }
                }
            }

        } catch (IOException e) {
            System.out.println("Failed to open file!");
            return;
        }

        if(!userExists){
            System.out.println("This user does not exist!");
            return;
        }

        //rewrite everything except new user
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
            for (Map<String, List<String>> line : fileLinesToRewrite) {
                outputStream.writeObject(line);
            }
        } catch (IOException e) {
            System.out.println("Error on server side!");
        }

        System.out.println("User successfuly removed.");

    }
    @SuppressWarnings("unchecked")
    private static void login(String username, String path) {

        LinkedList<Map<String, List<String>>> fileLinesToRewrite = new LinkedList<>();

        //check if user exists
        boolean userExists = false;
        String oldPassword = null;
        byte[] oldSalt = null;
        String oldForcepass = null;
        try{

            FileInputStream fileInputStream = new FileInputStream(path);
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            Map<String, List<String>> inputToBeRead = new HashMap<>();

            LinkedList<Map<String, List<String>>> readAllLines = new LinkedList<>();

            while (true) {
                try {
                    //read next line
                    inputToBeRead = (Map<String, List<String>>) objectInputStream.readObject();
                    readAllLines.add(inputToBeRead);
                } catch (IOException | ClassNotFoundException e) {
                    //System.out.println("Reached end of file.");
                    break;
                }
            }

            for(Map<String, List<String>> map : readAllLines) {
                for(Map.Entry<String, List<String>> entry : map.entrySet()){
                    String key = entry.getKey(); // Get the key
                    List<String> values = entry.getValue();

                    if(Arrays.equals(username.toCharArray(), key.toCharArray())) {
                        //System.out.println("This user already exists in file!");
                        userExists = true;

                        oldPassword = values.get(0);
                        String salt = values.get(1);
                        oldSalt = Base64.getDecoder().decode(salt);
                        oldForcepass = values.get(2);

                    } else {
                        fileLinesToRewrite.add(map);
                    }
                }
            }

        } catch (IOException e) {
            System.out.println("Failed to open file!");
            return;
        }

        if(!userExists){
            System.out.println("Username or password incorrect.");
            return;
        }

        //check password - max 3 times if incorrect
        int i = 0;
        char[] password = null;
        while(true) {
            password = System.console().readPassword("Password:");

            //check password1 - repeating
            String newPassHash = AuthUtils.hashPassword(password, oldSalt);
            if(Arrays.equals(newPassHash.toCharArray(), oldPassword.toCharArray())) {
                break;
            } else {
                System.out.println("Username or password incorrect.");
            }

            i++;
            if(i == 3) {
                System.out.println("Login failed!");
                return;
            }

        }


        //check forcepass - optinaly set new password - file rewriting
        if(Arrays.equals(oldForcepass.toCharArray(), "yes".toCharArray())) {

            char[] newPassword1 = System.console().readPassword("New password:");
            char[] newPassword2 = null;
            //check password1
            if(AuthUtils.checkPasswordConstr(newPassword1)) {
                newPassword2 = System.console().readPassword("Repeat new password:");
            } else {
                return;
            }

            //check pass1 and pass2 matching
            if (!Arrays.equals(newPassword1, newPassword2)) {
                System.out.println("Password change failed. Mismatch.");
                return;
            } else {

                Map<String, List<String>> outputToBeSaved = new HashMap<>();

                //hash password
                byte[] salt = AuthUtils.genSalt();
                String hashPassStr = AuthUtils.hashPassword(newPassword2, salt);

                //store username, password, salt and forcepass in file
                String key = username;
                List<String> values = new ArrayList<>();
                values.add(hashPassStr);
                values.add(Base64.getEncoder().encodeToString(salt));
                values.add("no");
                outputToBeSaved.put(key, values);
                fileLinesToRewrite.add(outputToBeSaved);

                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(path);
                    ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
                    for (Map<String, List<String>> line : fileLinesToRewrite) {
                        outputStream.writeObject(line);
                    }
                } catch (IOException e) {
                    System.out.println("Error on server side!");
                }
                System.out.println("Password change successful.");
            }

        }


        //start some process - https://www.geeksforgeeks.org/java-lang-process-class-java/
        try {

            // create a new process
            System.out.println("Creating Process");
            ProcessBuilder builder = new ProcessBuilder("notepad.exe");
            Process pro = builder.start();

            // wait 10 seconds
            System.out.println("Waiting");
            Thread.sleep(10000);

            // kill the process
            pro.destroyForcibly();
            System.out.println("Process destroyed");
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }



    }


    private static class AuthUtils{


        //recycle code from lab1 -> hashing function
        private static String hashPassword(char[] password, byte[] salt) {

            String hashPassStr = null;
            int interationCount = 310000;
            int derivedKeyLength = 256;

            try {
                //key generation
                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec keySpec = new PBEKeySpec(password, salt, interationCount, derivedKeyLength);
                //hashing
                byte[] hashPass = secretKeyFactory.generateSecret(keySpec).getEncoded();
                //hash into string
                hashPassStr = Base64.getEncoder().encodeToString(hashPass);
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Error on server side!");
                System.exit(-1);
            } catch (InvalidKeySpecException e) {
                System.out.println("Error on server side!");
                System.exit(-1);
            }

            return hashPassStr;

        }

        private static byte [] genSalt() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            return salt;

        }

        private static boolean checkPasswordConstr(char[] password) {

            boolean hasLower = false;
            boolean hasUpper = false;
            boolean hasDigit = false;
            boolean hasSpecial = false;

            Set<Character> set = new HashSet<Character>(Arrays.asList('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+'));

            if(password.length < 8) {
                System.out.println("The password must have at least eight characters!");
                return false;
            }

            for(char c : password) {
                if(Character.isLowerCase(c)) {
                    hasLower = true;
                }
                if(Character.isUpperCase(c)) {
                    hasUpper = true;
                }
                if(Character.isDigit(c)) {
                    hasDigit = true;
                }
                if(set.contains(c)) {
                    hasSpecial = true;
                }
            }

            if(!hasLower || !hasUpper || !hasDigit || !hasSpecial){
                System.out.println("The password must have at least one lowercase character, one uppercase character, one digit and one special character!");
                return false;
            }

            return true;
        }

    }

}
