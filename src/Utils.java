import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;

/**
 * Created by 45858000w on 07/12/16.
 */
public class Utils {

    /**
     * comprueba si existen los archivos private.key y public.key
     * @return
     * @param ficheroPublico
     * @param ficheroPrivate
     */
    public static boolean areKeysPresent(String ficheroPublico, String ficheroPrivate) {
        File filePub= new File(ficheroPublico);
        File filePriv= new File(ficheroPrivate);
        if(filePub.exists())
        {
            if(filePriv.exists())
            {
                System.out.println("Existen los dos archivos");
                return true;
            }
            else
            {
                System.out.println("No existe el archivo de Private.Key");
                return false;
            }
        }
        else
        {
            if(filePriv.exists())
            {
                System.out.println("No existe el archivo de Public.Key");
                return false;
            }
            else
            {
                System.out.println("No existen ninguno de los archivos");
                return false;
            }
        }

    }

    /**
     * generar les claus públiques i les claus privades
     * @return
     * @param ficheroPublico
     * @param ficheroPrivate
     */
    public static KeyPair generateKey(String ficheroPublico, String ficheroPrivate) throws IOException {
        KeyPair clave = null;//La clase KeyPair soporta una clave privada y una pública.
        try {
//Usamos el algoritmo RSA (RSA es un sistema criptográfico de clave pública desarrollado en 1977).
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            generador.initialize(1024);//Tamaño de la clave.

            clave = generador.genKeyPair();

            System.out.println("Clave privada: "+clave.getPrivate().toString());
            System.out.println("Clave pública: "+clave.getPublic().toString());


            File publicKeyFile= new File(ficheroPublico);
            if (publicKeyFile.getParentFile()==null)
            {
                publicKeyFile.getParentFile();
            }
            publicKeyFile.createNewFile();
            ObjectOutputStream pub = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            pub.writeObject(clave.getPublic());

            File privateKeyFile= new File(ficheroPrivate);
            if (privateKeyFile.getParentFile()==null)
            {
                privateKeyFile.getParentFile();
            }
            privateKeyFile.createNewFile();
            ObjectOutputStream priv = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            priv.writeObject(clave.getPublic());


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return clave;
    }

    /**
     * obtenir el HASH d'un fitxer. fer servir l'algoritme MD5
     * Per a encriptar el hash emprarem l'algoritme RSA (però guardeu el nom de l'algoritme en una variable global per si es volgués canviar)
     * @param f direccion del archivo

     * @return
     */
    public static byte[] getCodigoHash(File f, String md5) throws NoSuchAlgorithmException, IOException {
        {
            MessageDigest digest = MessageDigest.getInstance(md5);
            InputStream is = new FileInputStream(f);
            byte[] buffer = new byte[(int) f.length()];
            int read = 0;
            while ((read = is.read(buffer)) > 0)
            {
                digest.update(buffer, 0, read);
            }
            byte[] md5sum = digest.digest();
            BigInteger bigInt = new BigInteger(1, md5sum);
            String output = bigInt.toString(16);
            is.close();
            //return output;
            return md5sum;
        }
    }


    public static byte[] signar(byte[] hash, PrivateKey prik) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cifrado = Cipher.getInstance("RSA");
        cifrado.init(Cipher.ENCRYPT_MODE, prik);//MODO CIFRAR
        byte[] buffer= cifrado.doFinal(hash);

        return buffer;
    }

    public static byte[] desSignar(byte[] hash, PrivateKey prik) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cifrado = Cipher.getInstance("RSA");
        cifrado.init(Cipher.DECRYPT_MODE, prik);//MODO CIFRAR
        byte[] buffer= cifrado.doFinal(hash);

        return buffer;
    }

    /**
     * La funció read passar un fitxer a un array de bytes.
     * @param f
     */
    public static byte[] read(File f) throws IOException {
        FileInputStream ficheroStream = new FileInputStream(f);
        byte contenido[] = new byte[(int)f.length()];
        ficheroStream.read(contenido);
        return contenido;
    }

    /**
     * concatenar los dos bytes
     * @param fitxerLectura
     * @param encryptHash
     * @return
     */
    public static byte[] concatenateByteArrays(byte[] fitxerLectura, byte[] encryptHash) {
        byte concatenado[] = new byte[fitxerLectura.length+encryptHash.length];
        System.arraycopy(fitxerLectura, 0, concatenado, 0, fitxerLectura.length);
        System.arraycopy(encryptHash, 0, concatenado, fitxerLectura.length, encryptHash.length);
        return concatenado;
    }


    /**
     * La funció write guarda un array de bytes en un fitxer.
     * @param fitxerSignat
     * @param byteArray
     */
    public static void write(String fitxerSignat, byte[] byteArray) throws IOException {
        FileOutputStream fos = new FileOutputStream(fitxerSignat);
        fos.write(byteArray);

    }


    public static boolean compararFicheroHash(File file, String hashCode) throws NoSuchAlgorithmException, FileNotFoundException, IOException
    {
        return hashCode.equals(getCodigoHash(file,"MD5"));
    }

    public static boolean compararFicheros(File file1, File file2) throws NoSuchAlgorithmException, FileNotFoundException, IOException
    {
        return getCodigoHash(file1,"MD5").equals(getCodigoHash(file2,"MD5"));
    }
}
