import java.io.Serializable;
import java.security.Key;

/**
 * Created by Shawrup on 4/25/2016.
 */
public class Certificate implements Serializable{
    String owner;
    Key key;
    String issuer;

    public Certificate(String owner, Key key) {
        this.owner = owner;
        this.key = key;
        this.issuer = "CA";
    }
}
