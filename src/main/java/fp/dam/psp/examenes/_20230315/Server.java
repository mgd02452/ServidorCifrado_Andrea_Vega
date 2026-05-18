package fp.dam.psp.examenes._20230315;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;

public class Server {

    private static final int PORT = 9000;
    private static final int TIMEOUT = 5000;

    private static KeyStore keyStore;
    private static final char[] PASSWORD = "practicas".toCharArray();
    private static final String KEYSTORE_FILE = "keystore.p12";

    public static void main(String[] args) {
        try {
            cargarKeyStore();

            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Servidor iniciado en puerto " + PORT);

            while (true) {
                Socket socket = serverSocket.accept();

                Thread hilo = new Thread(() -> manejarCliente(socket));
                hilo.start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void cargarKeyStore() throws Exception {
    	keyStore = KeyStore.getInstance("PKCS12");
        Path path = Path.of(KEYSTORE_FILE);

        if (Files.exists(path)) {
            try (var in = Files.newInputStream(path)) {
                keyStore.load(in, PASSWORD);
            }
        } else {
            keyStore.load(null, PASSWORD);
        }
    }

    private static synchronized void guardarKeyStore() throws Exception {
        try (var out = Files.newOutputStream(Path.of(KEYSTORE_FILE))) {
            keyStore.store(out, PASSWORD);
        }
    }

    private static void manejarCliente(Socket socket) {
        try (
                socket;
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())
        ) {

            socket.setSoTimeout(TIMEOUT);

            String peticion;

            try {
                peticion = in.readUTF();
            } catch (SocketTimeoutException e) {
                out.writeUTF("ERROR:timeout leyendo petición");
                return;
            } catch (EOFException e) {
                out.writeUTF("ERROR:EOF leyendo petición");
                return;
            }

            switch (peticion) {
                case "hash":
                    procesarHash(in, out);
                    break;

                case "cert":
                    procesarCertificado(in, out);
                    break;

                case "cifrar":
                    procesarCifrado(in, out);
                    break;

                default:
                    out.writeUTF("ERROR:'" + peticion + "' no se reconoce como una petición válida");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void procesarHash(DataInputStream in, DataOutputStream out) {
        try {
            String algoritmo;

            try {
                algoritmo = in.readUTF();
            } catch (SocketTimeoutException e) {
                out.writeUTF("ERROR:timeout leyendo nombre de algoritmo");
                return;
            } catch (EOFException e) {
                out.writeUTF("ERROR:EOF leyendo nombre de algoritmo");
                return;
            }

            byte[] datos = leerBytes(in, out);

            if (datos == null)
                return;

            MessageDigest md = MessageDigest.getInstance(algoritmo);
            byte[] resumen = md.digest(datos);

            String b64 = Base64.getEncoder().encodeToString(resumen);

            out.writeUTF("OK:" + b64);

        } catch (Exception e) {
            try {
                out.writeUTF("ERROR:algoritmo inválido");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static void procesarCertificado(DataInputStream in, DataOutputStream out) {
        try {
            String alias;

            try {
                alias = in.readUTF();
            } catch (SocketTimeoutException e) {
                out.writeUTF("ERROR:timeout leyendo alias");
                return;
            } catch (EOFException e) {
                out.writeUTF("ERROR:EOF leyendo alias");
                return;
            }

            String certificadoB64;

            try {
                certificadoB64 = in.readUTF();
            } catch (SocketTimeoutException e) {
                out.writeUTF("ERROR:timeout leyendo certificado");
                return;
            } catch (EOFException e) {
                out.writeUTF("ERROR:EOF leyendo certificado");
                return;
            }

            byte[] certBytes;

            try {
                certBytes = Base64.getDecoder().decode(certificadoB64);
            } catch (IllegalArgumentException e) {
                out.writeUTF("ERROR:se esperaba Base64");
                return;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

            keyStore.setCertificateEntry(alias, cert);
            guardarKeyStore();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(certificadoB64.getBytes());

            String hashB64 = Base64.getEncoder().encodeToString(md.digest());

            out.writeUTF("OK:" + hashB64);

        } catch (Exception e) {
            try {
                out.writeUTF("ERROR:certificado inválido");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static void procesarCifrado(DataInputStream in, DataOutputStream out) {
        try {
            String alias;

            try {
                alias = in.readUTF();
            } catch (SocketTimeoutException e) {
                out.writeUTF("ERROR:timeout leyendo alias");
                return;
            } catch (EOFException e) {
                out.writeUTF("ERROR:EOF leyendo alias");
                return;
            }

            if (!keyStore.containsAlias(alias)) {
                out.writeUTF("ERROR:'" + alias + "' no es un certificado");
                return;
            }

            Certificate cert = keyStore.getCertificate(alias);
            PublicKey key = cert.getPublicKey();

            if (!key.getAlgorithm().equalsIgnoreCase("RSA")) {
                out.writeUTF("ERROR:'" + alias + "' no contiene una clave RSA");
                return;
            }

            byte[] datos = leerBytes(in, out);

            if (datos == null)
                return;

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            int bloque = 245;
            int totalBloques = (int) Math.ceil((double) datos.length / bloque);

            for (int i = 0; i < totalBloques; i++) {

                int inicio = i * bloque;
                int longitud = Math.min(bloque, datos.length - inicio);

                byte[] fragmento = new byte[longitud];
                System.arraycopy(datos, inicio, fragmento, 0, longitud);

                byte[] cifrado = cipher.doFinal(fragmento);

                String b64 = Base64.getEncoder().encodeToString(cifrado);

                out.writeUTF("OK:" + b64);
            }

            out.writeUTF("FIN:CIFRADO");
        } catch (Exception e) {
            try {
                out.writeUTF("ERROR:cifrado fallido");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static byte[] leerBytes(DataInputStream in, DataOutputStream out) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        byte[] bloque = new byte[1024];

        try {
            int leidos;

            while ((leidos = in.read(bloque)) != -1) {
                buffer.write(bloque, 0, leidos);
            }

        } catch (SocketTimeoutException e) {
            out.writeUTF("ERROR:timeout leyendo datos");
            return null;
        }

        if (buffer.size() == 0) {
            out.writeUTF("ERROR:EOF leyendo datos");
            return null;
        }

        return buffer.toByteArray();
    }
}
