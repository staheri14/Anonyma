import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;
import java.util.List;

/**
 * Created by stahe on 4/26/2019.
 */
public class RunTımeTest {
    //List<User> members;
    static int M=0;
    public static void main(String[] args) throws Exception {
        Server s = Server.getInstance();
        //initialize M members
        for(int i=0;i<M;i++){
            s.Reg(i); //this function creates a user with index i and adds to the server's list of users
        }
        //next time continue from here
        BigInteger[] t = s.TokenGeneration();

        Inviter inv = new Inviter();
        User u2 = s.users.get(2);
        User u4 = s.users.get(4);
        User u7 = s.users.get(7);
        User u8 = s.users.get(8);
        User u9 = s.users.get(9);

        Invitation i2 = inv.Igen(t, u2.getShare(), (PublicKey) s.vk, (Key) s.ek);
        Invitation i4 = inv.Igen(t, u4.getShare(), (PublicKey) s.vk, (Key) s.ek);
        Invitation i7 = inv.Igen(t, u7.getShare(), (PublicKey) s.vk, (Key) s.ek);
        Invitation i8 = inv.Igen(t, u8.getShare(), (PublicKey) s.vk, (Key) s.ek);
        Invitation i9 = inv.Igen(t, u9.getShare(), (PublicKey) s.vk, (Key) s.ek);

        Invitee invitee = new Invitee();
        Invitation[] invitations = { i2, i4, i7, i8, i9 };
        Invitation letter = invitee.Icoll(invitations, s.ek, t);

        boolean n = s.verify(letter, t);

        System.out.println("The veridict is: " + n);

    }
}
