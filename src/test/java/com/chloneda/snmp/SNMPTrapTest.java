package com.chloneda.snmp;

import org.junit.Before;
import org.junit.Test;
import org.snmp4j.mp.SnmpConstants;

/**
 * Created by chloneda
 * Description:
 */
public class SNMPTrapTest {

    @Before
    public void init(){
        //Snmp trap
        SNMPQuery snmpQuery = new SNMPQuery("192.167.1.120",1623, SnmpConstants.version3,"public");
    }

    @Test
    public void testTrap(){
        SNMPTrap trapReceiver = new SNMPTrap(
                "192.167.2.120", 1623, SnmpConstants.version3, "public");
    }
}
