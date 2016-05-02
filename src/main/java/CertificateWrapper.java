import java.io.Serializable;

/**
 * Created by Shawrup on 4/26/2016.
 */
public class CertificateWrapper implements Serializable{
    Certificate certificate;
    byte[] encryptedhash;

    public CertificateWrapper(Certificate certificate, byte[] encryptedhash) {
        this.certificate = certificate;
        this.encryptedhash = encryptedhash;
    }
}
