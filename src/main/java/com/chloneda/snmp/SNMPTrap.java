package com.chloneda.snmp;

import org.snmp4j.*;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;
import java.util.Vector;

/**
 * Created by chloneda
 * Description:
 *      SNMP Trap多线程接收解析信息
 */
public class SNMPTrap implements CommandResponder {

    private static TransportMapping<UdpAddress> transport = null;
    private MultiThreadedMessageDispatcher dispatcher;
    private Snmp snmp = null;
    private Address listenAddress;
    private ThreadPool threadPool;

    private int version;
    private String host;
    private int port;
    private String community;


    public SNMPTrap(String host, int port, int version, String community) {
        this.host = host;
        this.port = port;
        this.version = version;
        this.community = community;

        try {
            listen();
        } catch (IOException e) {
            e.printStackTrace();
        }
        snmp.addCommandResponder(this);
        System.out.println("---- Trap Receiver listening，waiting Trap message  ----");
    }

    private void listen() throws IOException {
        threadPool = ThreadPool.create("SnmpTrap", 3);
        dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());
        //listenAddress = GenericAddress.parse("udp:" + host + "/" + port);
        listenAddress = new UdpAddress(host + "/" + port);
        TransportMapping transport;
        if (listenAddress instanceof UdpAddress) {
            transport = new DefaultUdpTransportMapping((UdpAddress) listenAddress);
        } else {
            transport = new DefaultTcpTransportMapping((TcpAddress) listenAddress);
        }
        snmp = new Snmp(dispatcher, transport);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());

        if (version == SnmpConstants.version3) {
            USM usm = new USM(
                    SecurityProtocols.getInstance().addDefaultProtocols(),
                    new OctetString(MPv3.createLocalEngineID()), 0);
            usm.setEngineDiscoveryEnabled(true);
            SecurityModels.getInstance().addSecurityModel(usm);

            snmp.getUSM().addUser(
                    new OctetString("snmpuser"),
                    new UsmUser(new OctetString("snmpuser"), AuthMD5.ID,
                            new OctetString("auth123456"), PrivDES.ID,
                            new OctetString("priv123456")));

            SecurityModels.getInstance().addSecurityModel(usm);
        }

        snmp.listen();
    }


    @Override
    public void processPdu(CommandResponderEvent event) {
        System.out.println("---- Begin ----");
        if (event == null || event.getPDU() == null) {
            System.out.println("ResponderEvent or PDU is null!");
            return;
        }
        Vector<? extends VariableBinding> vbs = event.getPDU().getVariableBindings();
        for (VariableBinding vb : vbs) {
            String key=vb.getOid().toString();
            String value=vb.getVariable().toString();
            System.out.println(key + " = " + value);
        }
        System.out.println("---- End ----");
    }

    public static void main(String[] args) {
        SNMPTrap trapReceiver = new SNMPTrap(
                "192.167.2.120", 1623, SnmpConstants.version3, "public");
    }

}
