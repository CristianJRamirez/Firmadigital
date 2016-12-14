import java.io.*;
import java.security.*;

/**
 * Created by 45858000w on 07/12/16.
 */
public class P01_Encriptar {

    public static final String PRIVATE_KEY_FILE = "private.key";

    public static final String FITXER_PLA = "UF1-NF1-P01-Signatura.pdf";
    public static final String FITXER_SIGNAT = "firmat.pdf";
    public static final String ficheroPublico= "Public.key";
    public static final String ficheroPrivate= "Private.key";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {

        KeyPair keyPair = null;
        PrivateKey prik = null;

        File f = new File(FITXER_PLA);

        if(!Utils.areKeysPresent(ficheroPublico,ficheroPrivate)){//comprueba si hay archivos private.key y public.key, sino estan las crea
            keyPair = Utils.generateKey(ficheroPublico,ficheroPrivate);
            prik = keyPair.getPrivate();
        }else{
            ObjectInputStream inputStream = null;
            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            prik = (PrivateKey) inputStream.readObject();
        }

        byte[] hash = Utils.getCodigoHash(f,"MD5");
        byte[] encryptHash = Utils.signar(hash,prik);

        System.out.println("Longitud del fitxer: "+f.length());
        System.out.println("Longitud de la firma: "+encryptHash.length);

        Utils.write(FITXER_SIGNAT,Utils.concatenateByteArrays(Utils.read(f),encryptHash));
    }

}