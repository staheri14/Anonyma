/**
 * Created by stahe on 4/26/2019.
 */
public class Time {

    //these fields keep the time for the indicated algorithm
    private static double init=0;
    private static double Tgen=0;
    private static double Igen=0;
    private static double Icoll=0;
    private static double IVrfy=0;
    private static double Reg=0;
    //these fields record the number of times each algorithm is get called
    static double initN=0;
    static double TgenN=0;
    static double IgenN=0;
    static double IcollN=0;
    static double IVrfyN=0;
    static double RegN=0;

    static double addInit(double v)
    {
        init+=v;
        return init;
    }

    static double addIgen(double v)
    {
        Igen+=v;
        return Igen;
    }

    static double addTgen(double v)
    {
        Tgen+=v;
        return Tgen;
    }

    static double addIcoll(double v)
    {
        Icoll+=v;
        return Icoll;
    }
    static double addReg(double v)
    {
        Reg+=v;
        return Reg;
    }
    static double addIvrfy(double v)
    {
        IVrfy+=v;
        return IVrfy;
    }

}
