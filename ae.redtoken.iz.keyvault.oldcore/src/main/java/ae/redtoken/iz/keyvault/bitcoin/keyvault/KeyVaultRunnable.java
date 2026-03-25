package ae.redtoken.iz.keyvault.bitcoin.keyvault;

import lombok.SneakyThrows;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class KeyVaultRunnable implements Runnable {

    static class KeyVaultTask {
        final KeyVault.KeyPath keyPath;
        final KeyVault.AbstractKeyVaultCall.AbstractCallConfig callConfig;
        BlockingQueue<byte[]> result = new LinkedBlockingQueue<>(1);

        KeyVaultTask(KeyVault.KeyPath keyPath, KeyVault.AbstractKeyVaultCall.AbstractCallConfig callConfig) {
            this.keyPath = keyPath;
            this.callConfig = callConfig;
        }
    }

    private final BlockingQueue<KeyVaultTask> tasks = new LinkedBlockingQueue<>();
    private final KeyVault keyVault;

    public KeyVaultRunnable(KeyVault keyVault) {
        this.keyVault = keyVault;
    }

    boolean running = true;

    @SneakyThrows
    byte[] executeTask(KeyVault.KeyPath keyPath, KeyVault.AbstractKeyVaultCall.AbstractCallConfig callConfig) {
        KeyVaultTask task = new KeyVaultTask(keyPath, callConfig);
        tasks.add(task);
        return task.result.take();
    }

    @SneakyThrows
    @Override
    public void run() {
        while (running) {
            KeyVaultTask task = tasks.take();
            byte[] result = keyVault.execute(task.keyPath, task.callConfig);
            task.result.put(result);
        }
    }
}
