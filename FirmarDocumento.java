/**
 * Created by 45858000w on 14/12/16.
 */
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class FirmarDocumento {

//................................................CIFRADO................................................//

    //METODO QUE UTILIZO PARA ALMACENAR EN FICHEROS
    static void almacenarEnFichero(byte[] datos,String file) throws IOException{
        FileOutputStream salida=new FileOutputStream(file);
        salida.write(datos);
        salida.close();
    }

    //GUARDO CLAVE PRIVADA EN FICHERO
    static void almacenarEnFicheroClavePrivada(String file, byte[] privada, byte[] salt) throws IOException{
        FileOutputStream salida=new FileOutputStream(file);
        salida.write(salt);
        salida.write(privada);
        salida.close();
    }

    //GENERO CLAVE QUE CIFRA LA CLAVE PRIVADA (CONTIENE EL PASSWORD Y EL SALT)
    static SecretKey generarClave(char[] pass, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException{
        PBEKeySpec pks=new PBEKeySpec(pass, salt, 10);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey clave=skf.generateSecret(pks);
        return clave;
    }

    //CIFRO LA CLAVE PRIVADA
    static byte[] CifrarClave(byte[] clavePrivada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        Cipher cifrador=Cipher.getInstance("PBEWithMD5AndDES");
        cifrador.init(Cipher.ENCRYPT_MODE, k);
        return cifrador.doFinal(clavePrivada);
    }

//................................................DESCIFRADO................................................//

    //LEO LA CLAVE PRIVADA CIFRADA ALMACENADA EN EL FICHERO Y LA RETORNO
    static byte[] leerDeFichero(String file, byte[] salt) throws IOException{
        FileInputStream entrada=new FileInputStream(file);
        entrada.read(salt, 0, 8);
        int dato=0;
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        while ((dato=entrada.read())!=-1){
            baos.write(dato);
        }
        return baos.toByteArray();
    }

    //METODOS PARA DESCIFRAR CLAVE PRIVADA (LE PASO LA CLAVE PRIVADA CIFRADA Y LA CLAVE CON LA QUE SE CIFRO)
    static byte[] descifrarClavePrivada(byte[] clavePrivadaCifrada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher ci=Cipher.getInstance("PBEWithMD5AndDES");
        ci.init(Cipher.DECRYPT_MODE, k);
        return ci.doFinal(clavePrivadaCifrada);
    }

    static byte[] Descifrar() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        String password,file;
        char[] passwordCharA;
        byte[] salt=new byte[8];
        byte[] clavePrivadaCifrada;
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));

        System.out.println("\nIntroduce el password para descifrar la clave privada: ");
        password=br.readLine();
        passwordCharA=password.toCharArray();

        System.out.println("\nIntroduce el nombre del fichero donde se encuentra la clave privada");
        file=br.readLine();
        clavePrivadaCifrada=leerDeFichero(file,salt);
        SecretKey clave=generarClave(passwordCharA, salt);
        byte[] clavePrivadaDescifrada= descifrarClavePrivada(clavePrivadaCifrada, clave);

        System.out.println("\nClave Privada Descifrada! ");
        return clavePrivadaDescifrada;
    }

//................................................GESTION DE LA FIRMA Y CLAVE PUBLICA................................................//

    //METODO QUE UTILIZO PARA RECUPERAR CLAVE PUBLICA Y CLAVE PRIVADA Y DATOS DEL DOCUEMENTO
    static byte[] recuperarClavePPD(String file) throws IOException{
        FileInputStream entrada=new FileInputStream(file);
        int dato=0;
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        while ((dato=entrada.read())!=-1){
            baos.write(dato);
        }
        return baos.toByteArray();
    }

    //METODO PARA MOSTRAR DATOS DEL DOCUMENTO
    public static void mostrarDatos(byte [] datos) {
        System.out.write(datos, 0, datos.length);
    }


    //MAIN
    public static void main(String[] args) throws IOException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException {
       // Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
        BufferedReader teclado= new BufferedReader(new InputStreamReader(System.in));
        FileOutputStream salida = null;
        FileInputStream entrada = null;

        //VARIABLES QUE UTILIZO
        String fichero,password,datos,textoPlano;
        char[] passwordCharA;
        byte[] salt=new byte[8];
        byte [] clavePrivadaCifrada,documento,publica,privada,firma,datosDeFirma,datosDocumento,textoCifradoByte,claveSimetricaCifradaConClavePublica,data1,claveCifradaConPublica,claveDescifrada,textoDocumento;
        int op;


        System.out.println("\nPRIMERA PARTE:..............................GENERAR Y ALMACENAR EL PAR DE CLAVES.....................................\n");

        //GENERAR Y ALMACENAR EL PAR DE CLAVES
        KeyPairGenerator kg=KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        KeyPair kp=kg.generateKeyPair();

        //OBTENGO CLAVE PUBLICA Y PRIVADA A PARATIR DE KEYPAIRGENERATOR Y KEYPAIR
        PublicKey kpu=kp.getPublic();
        PrivateKey kpr=kp.getPrivate();

        //CONVIERTO LAS CLAVES EN BYTES PARA GUARDAR EN FICHERO
        publica=kpu.getEncoded();
        privada=kpr.getEncoded();

        //GUARDO LA CLAVE PUBLICA EN UN FICHERO EXTERNO
        System.out.println("Nombre fichero para clave publica? ");
        fichero=teclado.readLine();
        almacenarEnFichero(publica,fichero);

        //ENCRIPTO CLAVE PRIVADA CON PASSWORD Y SALT (PBE)
        System.out.println("\nIntroduce el password para cifrar la clave privada: ");
        password=teclado.readLine();
        passwordCharA=password.toCharArray();

        //CREO UN SALT Y GENERO SECRETKEY
        SecureRandom sc=SecureRandom.getInstance("SHA1PRNG");
        sc.nextBytes(salt);
        SecretKey clave=generarClave(passwordCharA,salt);

        //CIFRO CLAVE PRIVADA CON LA CLAVE QUE CONTIENE EL SALT Y EL PASSWORD
        clavePrivadaCifrada=CifrarClave(privada,clave);

        //GUARDO LA CLAVE EN UN FICHERO EXTERNO
        System.out.println("Introduce nombre de fichero donde quieres guardar la clave privada? ");
        fichero=teclado.readLine();
        almacenarEnFicheroClavePrivada(fichero,clavePrivadaCifrada,salt);





        System.out.println("\nSEGUNDA PARTE:..............................FIRMAR DIGITALMENTE UN FICHERO.....................................\n");

        //SOLICITO EL TEXTO QUE QUIERO FIRMAR
        System.out.println("\nNombre de fichero donde guardaremos documento que queremos firmar: ");
        fichero=teclado.readLine();
        System.out.println("\nTexto del fichero para firmar: ");
        datos=teclado.readLine();
        documento=datos.getBytes();
        almacenarEnFichero(documento,fichero);

        //CLAVE PRIVADA, INVIERTO LA CONVERSION ENCODE Y PREPARO PARA FIRMAR
        PKCS8EncodedKeySpec privi=new PKCS8EncodedKeySpec(Descifrar());
        KeyFactory keyFactoryPrivada = KeyFactory.getInstance("RSA");
        PrivateKey privatekey = keyFactoryPrivada.generatePrivate(privi);

        //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PRIVADA LE PASO DATOS QUE QUIERO FIRMAR
        Signature firmaPrivada=Signature.getInstance("RSA");
        firmaPrivada.initSign(privatekey);
        firmaPrivada.update(documento);
        //CREO LA FIRMA
        datosDeFirma=firmaPrivada.sign();
        System.out.println("\nDocumento firmado con clave privada!\n ");

        //ALMACENO LA FIRMA EN UN FICHERO
        System.out.println("Introduce nombre de fichero para guardar la firma? ");
        fichero=teclado.readLine();
        almacenarEnFichero(datosDeFirma,fichero);





        System.out.println("\nTERCERA PARTE:..............................VERIFICAR FIRMA DIGITAL DE UN FICHERO.....................................\n\n");

        //RECUPERO CLAVE PUBLICA
        System.out.println("Introduce nombre de fichero que contiene la clave publica? ");
        fichero=teclado.readLine();

        //CLAVE PUBLICA, INVIERTO LA CONVERSION ENCODE Y PREPARO PARA VERIFICAR
        X509EncodedKeySpec pub=new X509EncodedKeySpec(recuperarClavePPD(fichero));
        KeyFactory keyFactoryPublico = KeyFactory.getInstance("RSA");
        PublicKey publickey = keyFactoryPublico.generatePublic(pub);

        //RECUPERO FIRMA
        System.out.println("Introduce nombre de fichero donde está la firma? ");
        fichero=teclado.readLine();
        firma=recuperarClavePPD(fichero);

        //RECUPERO DATOS DEL DOCUEMENTO
        System.out.println("Introduce nombre de fichero donde está el documento? ");
        fichero=teclado.readLine();
        datosDocumento=recuperarClavePPD(fichero);

        //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PUBLICA LE PASO DATOS DEL DOCUMENTO
        Signature firmaPublica=Signature.getInstance("RSA");
        firmaPublica.initVerify(publickey);
        firmaPublica.update(datosDocumento);

        //VERIFICO FIRMA CON CLAVE PUBLICA
        if (firmaPublica.verify(firma) == true)
            System.out.println("Firma verificada!!!\n\n");
        else
            System.out.println("Firma no valida\n\n");

        //MUESTRO LOS DATOS GUARDADOS EN EL FICHERO
        mostrarDatos(datosDocumento);





        System.out.println("\n\nCUARTA PARTE:..................CIFRAR Y DESCIFRAR UN FICHERO UTILIZANDO UNA CLAVE DE SESION...................\n" +
                "...................................UTILIZO EL PAR DE CLAVES GENERADOS EN LA PRIMERA PARTE.....................................\n");

        //CREO CLAVE DE SESION (CLAVE SIMETRICA)
        KeyGenerator kg1=KeyGenerator.getInstance("DES");
        kg1.init(56);
        SecretKey claveSimetrica=kg1.generateKey();
        Cipher cifrador=Cipher.getInstance("DES");
        cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);

        //ENCRIPTO Y GUARDO TEXTO ENCRIPTADO EN FICHERO
        System.out.println("\nIntroduce nombre de fichero donde quieres guardar los datos? ");
        fichero=teclado.readLine();
        try {
            salida=new FileOutputStream(fichero+".txt");
            do{
                System.out.println("Dame la informacion que deseas cifrar? ");
                textoPlano="\n"+teclado.readLine();

                //ENCRIPTO CADENA
                textoCifradoByte=cifrador.doFinal(textoPlano.getBytes("UTF-8"));

                //ESCRIBO CADENA CIFRADA EN FICHERO
                salida.write(textoCifradoByte);
                System.out.println("más texto? (S/N)");
                op=teclado.readLine().charAt(0);
            }while(op=='s');
        }catch (IOException ex){System.out.println(ex);}
        finally{
            if(salida!=null){
                try{salida.close();}catch(IOException ex){}
            }
        }

        //RECUPERO CLAVE PUBLICA
        System.out.println("Introduce nombre de fichero que contiene la clave publica? ");
        fichero=teclado.readLine();

        //INVIERTO LA CONVERSION ENCODE
        X509EncodedKeySpec clavepublica=new X509EncodedKeySpec(recuperarClavePPD(fichero));
        KeyFactory keyFactoryPublico1 = KeyFactory.getInstance("RSA");
        PublicKey publickey1 = keyFactoryPublico1.generatePublic(clavepublica);

        //CIFRO LA CLAVE SIMETRICA(DE SESION) CON LA CLAVE(ASIMETRICA) PUBLICA PARA PODER TRANSPORTARLA
        Cipher ci=Cipher.getInstance("RSA");
        ci.init(Cipher.ENCRYPT_MODE,publickey1);
        claveSimetricaCifradaConClavePublica=ci.doFinal(claveSimetrica.getEncoded());

        //GUARDO CLAVE SIMETRICA CIFRADA CON CLAVE PUBLICA EN FICHERO
        System.out.println("Nombre de fichero para guardar la clave simetrica cifrada con clave publica? ");
        fichero=teclado.readLine();
        almacenarEnFichero(claveSimetricaCifradaConClavePublica,fichero);

        //LEO FICHERO CON DATOS ENCRIPTADOS
        System.out.println("Nombre de fichero donde guardaste los datos cifrados con clave simetrica? ");
        fichero=teclado.readLine();
        data1=null;
        try{
            entrada= new FileInputStream(fichero+".txt");
            data1 = new byte[entrada.available()];
            entrada.read(data1);
        }catch (Exception e) {e.printStackTrace();}
        finally{
            if(entrada!=null){
                try{entrada.close();}catch(IOException ex){}
            }
        }

        //RECUPERO CLAVE PRIVADA, INVIERTO LA CONVERSION ENCODE
        PKCS8EncodedKeySpec claveprivada=new PKCS8EncodedKeySpec(Descifrar());
        KeyFactory keyFactoryPrivada1 = KeyFactory.getInstance("RSA");
        PrivateKey privatekey1 = keyFactoryPrivada1.generatePrivate(claveprivada);

        //LEO FICHERO QUE CONTIENE LA CLAVE SIMETRICA ENCRIPTADA CON CLAVE PUBLICA
        System.out.println("Introduce nombre de fichero que contiene clave simetrica? ");
        fichero=teclado.readLine();
        claveCifradaConPublica=recuperarClavePPD(fichero);

        //DESENCRIPTO CLAVE SIMETRICA CON CLAVE PRIVADA
        ci.init(Cipher.DECRYPT_MODE,privatekey1);
        claveDescifrada=ci.doFinal(claveCifradaConPublica);

        //UTILIZO SECRETKEYSPEC PARA INVERTIR LA CONVERSION ENCODED Y LE PASO EL TIPO DE ALGORITMO
        SecretKey claveSimefinal=new SecretKeySpec(claveDescifrada,"DES");

        //DESENCRIPTO DATOS DE FICHERO
        cifrador.init(Cipher.DECRYPT_MODE,claveSimefinal);
        textoDocumento=cifrador.doFinal(data1);
        System.out.println(new String(textoDocumento));
    }
}