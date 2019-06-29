package com.chloneda.snmp;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;

import java.io.IOException;

/**
 * Created by chloneda
 * Description:
 */
public class SNMPQueryTest {
    SNMPQuery snmpQuery;

    @Before
    public void init(){
        //Snmp query
        snmpQuery = new SNMPQuery("192.167.1.120",161, SnmpConstants.version3,"public");

        //Snmp trap
        //snmpQuery = new SNMPQuery("192.167.1.120",1623, SnmpConstants.version1,"public");
    }

    @Test
    public void testSnmpGet() throws Exception {
        //get-request
        SNMPQuery.snmpGet("1.3.6.1.2.1.1.4.0");//sysContact
    }

    @Test
    public void testSnmpGetBulk() throws IOException {
        //getBulk-request
        SNMPQuery.snmpGetBulk("1.3.6.1.2.1.1");
    }

    @Test
    public void testSnmpSet(){
        //set-request
        //SNMPQuery.snmpSet(new OID("1.3.6.1.2.1.1.4.0"), new VariantVariable());
    }

    @Test
    public void testSnmpWalk() throws Exception {
        //getNext-request
        SNMPQuery.snmpWalk(new OID("1.3.6.1.2.1.2.2.1.2"), "WALK");//IfDescr
    }

    @Test
    public void testSnmpGetResponse() throws Exception {
        //get-response
        SNMPQuery.snmpGetResponse(false, true, "1.3.6.1.2.1.1.4.0");//sysContact
    }

    @Test
    public void testSendSnmpTrap() throws IOException {
        ResponseEvent event=SNMPQuery.sendSnmpTrap("1.3.6.1.2.1.1.4.0");
        System.out.println(event.getResponse());
    }

    @Test
    public void testSnmpReport(){
        //report
    }

    @Test
    public void testSnmpInformRequest(){
        //inform-request
    }

    @Test
    public void testSnmpTrap(){
        //trap
    }

    @After
    public void destory(){
        snmpQuery.destory();
    }

}
