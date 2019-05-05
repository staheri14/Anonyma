/**
 * Created by stahe on 4/26/2019.
 */
public class Time {

    //these fields keep the time for the indicated algorithm
    private  double init=0;
    private  double Tgen=0;
    private  double Igen=0;
    private  double Icoll=0;
    private  double IVrfy=0;
    private  double Reg=0;
    //these fields record the number of times each algorithm is get called
    static double initN=0;
    static double TgenN=0;
    static double IgenN=0;
    static double IcollN=0;
    static double IVrfyN=0;
    static double RegN=0;

    public Time(double tgen, double igen, double icoll, double IVrfyTime) {
        Tgen = tgen;
        Igen = igen;
        Icoll = icoll;
        IVrfy = IVrfyTime;
    }

    public double getTgen() {
        return Tgen;
    }

    public double getIgen() {
        return Igen;
    }

    public double getIcoll() {
        return Icoll;
    }

    public double getIVrfy() {
        return IVrfy;
    }
}
