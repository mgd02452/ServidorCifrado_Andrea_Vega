package fp.dam.psp.examenes._20230315;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.math3.util.Precision;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

@TestMethodOrder(MethodOrderer.MethodName.class)
class ServerTests {

	static float calificación;
	static KeyStore ks;
//	static SecretKey secretKey;
	
	@BeforeAll
	static void setUp() throws Exception {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(ServerTests.class.getResourceAsStream("/keystore.p12"), "practicas".toCharArray());
	}
	
	@AfterAll
	static void resultado() {
		System.out.println("Calificación: " + Precision.round(calificación, 2));
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) No se envía petición: TIMEOUT")
	void test01() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			assertEquals("ERROR:timeout leyendo petición", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) No se envía petición: EOF")
	void test02() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			socket.shutdownOutput();
			assertEquals("ERROR:EOF leyendo petición", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición incorrecta")
	void test03() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("abcd");
			assertEquals("ERROR:'abcd' no se reconoce como una petición válida", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(1,4 puntos) Petición \"hash\"")
	void test04() {
		String mensaje = "MENSAJE DE PRUEBA";
		for (String algoritmo: new String [] {"SHA-256", "MD5", "SHA3-512"}) {
			try (Socket socket = new Socket("localhost", 9000)){
				socket.setSoTimeout(1000);
				MessageDigest md;
				md = MessageDigest.getInstance(algoritmo);
				String hashB64 = Base64.getEncoder().encodeToString(md.digest(mensaje.getBytes()));
				
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				out.writeUTF("hash");
				out.writeUTF(algoritmo);
				out.write(mensaje.getBytes());
				socket.shutdownOutput();
				assertEquals("OK:" + hashB64, new DataInputStream(socket.getInputStream()).readUTF());
			} catch (IOException | NoSuchAlgorithmException e) {
				fail(e.getLocalizedMessage());
			}
		}
		calificación += 1.4;
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,4 puntos) Petición \"hash\" sin algoritmo: TIMEOUT")
	void test05() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			
			assertEquals("ERROR:timeout leyendo nombre de algoritmo", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.4;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin algoritmo: EOF")
	void test06() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo nombre de algoritmo", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos: TIMEOUT")
	void test07() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			
			assertEquals("ERROR:timeout leyendo datos", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin datos: EOF")
	void test08() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo datos", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"hash\" sin EOF")
	void test09() {
		String mensaje = "MENSAJE DE PRUEBA";
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("hash");
			out.writeUTF("SHA-256");
			out.write(mensaje.getBytes());
			
			assertEquals("ERROR:timeout leyendo datos", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(1,4 puntos) Petición \"cert\"")
	void test10() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(1000);
			String b64 = Base64.getEncoder().encodeToString(ks.getCertificate("psp").getEncoded());
			MessageDigest md;
			md = MessageDigest.getInstance("SHA-256");
			md.update(b64.getBytes());
			String b64HashB64 = Base64.getEncoder().encodeToString(md.digest());
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF(b64);
			socket.shutdownOutput();
			
			assertEquals("OK:" + b64HashB64, new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 1.4;
		} catch (IOException | CertificateEncodingException | NoSuchAlgorithmException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias: TIMEOUT")
	void test11() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			
			assertEquals("ERROR:timeout leyendo alias", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}	
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin alias: EOF")
	void test12() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo alias", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado: TIMEOUT")
	void test13() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			
			assertEquals("ERROR:timeout leyendo certificado", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin certificado: EOF")
	void test14() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo certificado", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cert\" sin codificar en Base64")
	void test15() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("psp");
			out.writeUTF("*****");
			
			assertEquals("ERROR:se esperaba Base64", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(3 puntos) Petición \"cifrar\"")
	void test16() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, "
					+ "adarga antigua, rocín flaco y galgo corredor. Una olla de algo más vaca que carnero, salpicón las más noches, duelos y quebrantos los sábados, "
					+ "lentejas los viernes, algún palomino de añadidura los domingos, consumían las tres partes de su hacienda. El resto della concluían sayo de velarte, "
					+ "calzas de velludo para las fiestas con sus pantuflos de lo mismo, los días de entre semana se honraba con su vellori de lo más fino. Tenía en su "
					+ "casa una ama que pasaba de los cuarenta, y una sobrina que no llegaba a los veinte, y un mozo de campo y plaza, que así ensillaba el rocín como "
					+ "tomaba la podadera. Frisaba la edad de nuestro hidalgo con los cincuenta años, era de complexión recia, seco de carnes, enjuto de rostro; gran "
					+ "madrugador y amigo de la caza. Quieren decir que tenía el sobrenombre de Quijada o Quesada (que en esto hay alguna diferencia en los autores que "
					+ "deste caso escriben), aunque por conjeturas verosímiles se deja entender que se llama Quijana; pero esto importa poco a nuestro cuento; basta que "
					+ "en la narración dél no se salga un punto de la verdad. Es, pues, de saber, que este sobredicho hidalgo, los ratos que estaba ocioso (que eran los más "
					+ "del año) se daba a leer libros de caballerías con tanta afición y gusto, que olvidó casi de todo punto el ejercicio de la caza, y aun la administración "
					+ "de su hacienda; y llegó a tanto su curiosidad y desatino en esto, que vendió muchas hanegas de tierra de sembradura, para comprar libros de caballerías "
					+ "en que leer; y así llevó a su casa todos cuantos pudo haber dellos; y de todos ningunos le parecían tan bien como los que compuso el famoso Feliciano "
					+ "de Silva: porque la claridad de su prosa, y aquellas intrincadas razones suyas, le parecían de perlas; y más cuando llegaba a leer aquellos requiebros "
					+ "y cartas de desafío, donde en muchas partes hallaba escrito: la razón de la sinrazón que a mi razón se hace, de tal manera mi razón enflaquece, que con "
					+ "razón me quejo de la vuestra fermosura, y también cuando leía: los altos cielos que de vuestra divinidad divinamente con las estrellas se fortifican, "
					+ "y os hacen merecedora del merecimiento que merece la vuestra grandeza. Con estas y semejantes razones perdía el pobre caballero el juicio, y desvelábase "
					+ "por entenderlas, y desentrañarles el sentido, que no se lo sacara, ni las entendiera el mismo Aristóteles, si resucitara para sólo ello. No estaba muy "
					+ "bien con las heridas que don Belianis daba y recibía, porque se imaginaba que por grandes maestros que le hubiesen curado, no dejaría de tener el rostro "
					+ "y todo el cuerpo lleno de cicatrices y señales; pero con todo alababa en su autor aquel acabar su libro con la promesa de aquella inacabable aventura, "
					+ "y muchas veces le vino deseo de tomar la pluma, y darle fin al pie de la letra como allí se promete; y sin duda alguna lo hiciera, y aun saliera con "
					+ "ello, si otros mayores y continuos pensamientos no se lo estorbaran.";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			
			DataInputStream in = new DataInputStream(socket.getInputStream());
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, ks.getKey("psp", "practicas".toCharArray()));
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			String[] s = null;
			try {
				while (true) {
					s = in.readUTF().split(":");
					assertTrue(s.length == 2);
					if (s[0].equals("OK")) {
						buffer.write(cipher.doFinal(Base64.getDecoder().decode(s[1].getBytes())));
					}
					else if (s[0].equals("ERROR"))
						fail(s[1]);
				}
			} catch (EOFException e) {
				assertEquals("FIN", s[0]);
				assertEquals("CIFRADO", s[1]);
				calificación += 3;
			}
			assertEquals(texto, new String(buffer.toByteArray()));	
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnrecoverableKeyException | KeyStoreException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias: TIMEOUT")
//	void test17() {
//		try (Socket socket = new Socket("localhost", 9000)){
//			socket.setSoTimeout(10000);
//			
//			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
//			out.writeUTF("cifrar");
//			
//			assertEquals("ERROR:timeout leyendo alias", new DataInputStream(socket.getInputStream()).readUTF());
//			calificación += 0.2;
//		} catch (IOException e) {
//			fail(e.getLocalizedMessage());
//		}
//	}
	
	void test17() {
	    try (Socket socket = new Socket("localhost", 9000)) {

	        socket.setSoTimeout(10000);

	        String texto = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20);

	        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

	        out.writeUTF("cifrar");
	        out.writeUTF("psp");
	        out.write(texto.getBytes());
	        socket.shutdownOutput();

	        DataInputStream in = new DataInputStream(socket.getInputStream());

	        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	        cipher.init(Cipher.DECRYPT_MODE,
	                ks.getKey("psp", "practicas".toCharArray()));

	        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

	        while (true) {
	            String respuesta = in.readUTF();

	            String[] partes = respuesta.split(":");

	            if (partes[0].equals("OK")) {

	                byte[] bloque = Base64.getDecoder().decode(partes[1]);

	                buffer.write(cipher.doFinal(bloque));

	            } else if (partes[0].equals("FIN")) {
	                break;
	            }
	        }

	        assertEquals(texto, new String(buffer.toByteArray()));

	        calificación += 0.2;

	    } catch (Exception e) {
	        fail(e.getLocalizedMessage());
	    }
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" sin alias: EOF")
	void test18() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo alias", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el alias no es válido")
	void test19() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("aliasnoválido");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			
			assertEquals("ERROR:'aliasnoválido' no es un certificado", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" el certificado no contiene una clave RSA")
	void test20() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(1000);
			String b64 = Base64.getEncoder().encodeToString(ks.getCertificate("alumno").getEncoded());
			MessageDigest md;
			md = MessageDigest.getInstance("SHA-256");
			md.update(b64.getBytes());
			String b64HashB64 = Base64.getEncoder().encodeToString(md.digest());
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cert");
			out.writeUTF("alumno");
			out.writeUTF(b64);
			assertEquals("OK:" + b64HashB64, new DataInputStream(socket.getInputStream()).readUTF());
		} catch (IOException | CertificateEncodingException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			fail(e.getLocalizedMessage());
		}
		
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("alumno");
			out.write(texto.getBytes());
			socket.shutdownOutput();
			
			assertEquals("ERROR:'alumno' no contiene una clave RSA", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" cliente no envía EOF")
	void test21() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			String texto = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme ...";
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			out.write(texto.getBytes());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			String s = null;
			try {
				while (true)
					s = in.readUTF();
			} catch (EOFException e) {
				assertTrue(s != null);
				assertEquals("ERROR:timeout leyendo datos", s);
				calificación += 0.2;
			}
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos")
	void test22() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			
			assertEquals("ERROR:timeout leyendo datos", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
	@SuppressWarnings("resource")
	@Test
	@DisplayName("(0,2 puntos) Petición \"cifrar\" no se envían datos (B)")
	void test23() {
		try (Socket socket = new Socket("localhost", 9000)){
			socket.setSoTimeout(10000);
			
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			out.writeUTF("cifrar");
			out.writeUTF("psp");
			socket.shutdownOutput();
			
			assertEquals("ERROR:EOF leyendo datos", new DataInputStream(socket.getInputStream()).readUTF());
			calificación += 0.2;
		} catch (IOException e) {
			fail(e.getLocalizedMessage());
		}
	}
	
} 
