import ae.redtoken.nostrjava.SimpleNostrEventHandler;

module ae.redtoken.nostrjava {
    requires nostr.command.handler;
    requires static lombok;
    requires nostr.base;
    requires nostr.context;
    requires nostr.event;
    requires java.logging;
    requires nostr.context.impl;
    requires nostr.util;
    requires nostr.crypto;
    requires com.fasterxml.jackson.databind;
    requires org.bouncycastle.provider;
    requires annotations;
    provides nostr.command.CommandHandler with SimpleNostrEventHandler;
}

