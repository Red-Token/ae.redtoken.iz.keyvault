import ae.redtoken.nostrtest.NostrTestEventHandler;

module ae.redtoken.iz.keyvault {
    requires nostr.command.handler;
    requires static lombok;
    requires nostr.base;
    requires nostr.context;
    requires nostr.event;
    requires java.logging;
    requires nostr.context.impl;
    requires org.slf4j;
    requires nostr.util;
    requires org.bitcoinj.core;
    requires nostr.crypto;
    requires com.fasterxml.jackson.databind;
    requires org.bouncycastle.pg;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires annotations;
    requires nostr.encryption;
    requires nostr.encryption.nip44dm;
    requires org.checkerframework.checker.qual;
    requires org.apache.sshd.common;
    requires org.jnrproject.unixsocket;
    requires net.i2p.crypto.eddsa;
    requires com.google.zxing;
    requires com.google.zxing.javase;
    requires org.apache.commons.logging;
    requires nostr.api;
    requires nostr.id;
//    requires ae.redtoken.iz.keyvault;
    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.annotation;
//    requires ae.redtoken.iz.keyvault;
    provides nostr.command.CommandHandler with NostrTestEventHandler;
    exports ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin to com.fasterxml.jackson.databind;
    exports ae.redtoken.iz.keyvault.bitcoin.stackedservices to com.fasterxml.jackson.databind;

    // This is the fix:
    opens ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin to com.fasterxml.jackson.databind;
    opens ae.redtoken.iz.keyvault.bitcoin.stackedservices to com.fasterxml.jackson.databind;

    exports ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr to com.fasterxml.jackson.databind;
    opens ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr to com.fasterxml.jackson.databind;

    exports ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh to com.fasterxml.jackson.databind;
    opens ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.ssh to com.fasterxml.jackson.databind;

    exports ae.redtoken.iz.keyvault.bitcoin.scenario to com.fasterxml.jackson.databind;

    exports ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem to nostr.event;
    opens ae.redtoken.iz.keyvault.bitcoin.keymasteravatar.messagesystem to com.fasterxml.jackson.databind;
}

