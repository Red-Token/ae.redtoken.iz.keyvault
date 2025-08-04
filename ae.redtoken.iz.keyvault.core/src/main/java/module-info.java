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
    provides nostr.command.CommandHandler with NostrTestEventHandler;
    exports ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin to com.fasterxml.jackson.databind;
    exports ae.redtoken.iz.keyvault.bitcoin.stackedservices to com.fasterxml.jackson.databind;

    // This is the fix:
    opens ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.bitcoin to com.fasterxml.jackson.databind;
    opens ae.redtoken.iz.keyvault.bitcoin.stackedservices to com.fasterxml.jackson.databind;

    exports ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr to com.fasterxml.jackson.databind;
    opens ae.redtoken.iz.keyvault.bitcoin.keymaster.services.protocol.nostr to com.fasterxml.jackson.databind;
}

