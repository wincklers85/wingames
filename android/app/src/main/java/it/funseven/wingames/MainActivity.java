package it.funseven.wingames;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Set;
import java.util.UUID;

public class MainActivity extends Activity {
    private static final int REQUEST_BT = 42;
    private static final String APP_URL = "https://wingames-gestionale-alfa.lastbonus128.chatgpt.site/";
    private static final String APP_HOST = "wingames-gestionale-alfa.lastbonus128.chatgpt.site";
    private static final UUID SPP_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    private WebView webView;
    private BluetoothAdapter bluetooth;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(16, 39, 31));
        getWindow().setNavigationBarColor(Color.rgb(16, 39, 31));
        bluetooth = BluetoothAdapter.getDefaultAdapter();
        webView = new WebView(this);
        webView.setBackgroundColor(Color.rgb(244, 245, 242));
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, false);
        webView.addJavascriptInterface(new PrinterBridge(), "WinGamesPrinter");
        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if ("https".equals(uri.getScheme()) && APP_HOST.equals(uri.getHost())) return false;
                try { startActivity(new Intent(Intent.ACTION_VIEW, uri)); } catch (Exception ignored) { }
                return true;
            }
        });
        setContentView(webView);
        webView.loadUrl(APP_URL);
    }

    private boolean hasBluetoothPermission() {
        return Build.VERSION.SDK_INT < 31 || checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED;
    }
    private void requestBluetoothPermission() {
        if (Build.VERSION.SDK_INT >= 31 && !hasBluetoothPermission()) runOnUiThread(() -> {
            if (!hasBluetoothPermission()) requestPermissions(new String[]{Manifest.permission.BLUETOOTH_CONNECT}, REQUEST_BT);
        });
    }
    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == REQUEST_BT && webView != null) webView.evaluateJavascript("window.dispatchEvent(new Event('wg-bluetooth-ready'))", null);
    }

    private class PrinterBridge {
        @JavascriptInterface public String getPairedPrinters() {
            if (bluetooth == null) return "[]";
            if (!hasBluetoothPermission()) { requestBluetoothPermission(); return "[]"; }
            try {
                Set<BluetoothDevice> bonded = bluetooth.getBondedDevices();
                JSONArray list = new JSONArray();
                for (BluetoothDevice device : bonded) {
                    JSONObject item = new JSONObject();
                    item.put("name", device.getName() == null ? "Stampante Bluetooth" : device.getName());
                    item.put("address", device.getAddress());
                    list.put(item);
                }
                return list.toString();
            } catch (Exception error) { return "[]"; }
        }
        @JavascriptInterface public void setPrinter(String address) {
            getSharedPreferences("wingames", MODE_PRIVATE).edit().putString("printer", address == null ? "" : address).apply();
        }
        @JavascriptInterface public void openBluetoothSettings() {
            runOnUiThread(() -> {
                try { startActivity(new Intent(android.provider.Settings.ACTION_BLUETOOTH_SETTINGS)); }
                catch (Exception error) { Toast.makeText(MainActivity.this, "Apri le impostazioni Bluetooth del telefono", Toast.LENGTH_LONG).show(); }
            });
        }
        @JavascriptInterface public void printReceipt(String text) {
            if (!hasBluetoothPermission()) { requestBluetoothPermission(); notifyPrinter(false, "Consenti l’accesso Bluetooth e riprova."); return; }
            final String address = getSharedPreferences("wingames", MODE_PRIVATE).getString("printer", "");
            if (address.isEmpty()) { notifyPrinter(false, "Seleziona prima la stampante nelle impostazioni."); return; }
            new Thread(() -> {
                BluetoothSocket socket = null;
                try {
                    if (bluetooth == null || !bluetooth.isEnabled()) throw new Exception("Attiva il Bluetooth del telefono.");
                    BluetoothDevice device = bluetooth.getRemoteDevice(address);
                    try {
                        socket = device.createRfcommSocketToServiceRecord(SPP_UUID);
                        socket.connect();
                    } catch (Exception secureError) {
                        try { if (socket != null) socket.close(); } catch (Exception ignored) { }
                        socket = device.createInsecureRfcommSocketToServiceRecord(SPP_UUID);
                        socket.connect();
                    }
                    OutputStream out = socket.getOutputStream();
                    out.write(new byte[]{0x1b, 0x40}); // ESC @, reset
                    out.write(new byte[]{0x1b, 0x74, 0x02}); // PC850
                    String safe = (text == null ? "" : text).replace("€", " EUR").replace("·", "-").replace("\r", "");
                    out.write(safe.getBytes(Charset.forName("Cp850")));
                    out.write(new byte[]{0x0a, 0x0a, 0x0a});
                    out.flush();
                    notifyPrinter(true, "Ricevuta inviata alla stampante.");
                } catch (Exception error) {
                    String message = error.getMessage() == null ? "Controlla che la stampante sia accesa e accoppiata." : error.getMessage();
                    notifyPrinter(false, message);
                } finally { try { if (socket != null) socket.close(); } catch (Exception ignored) { } }
            }).start();
        }
    }

    private void notifyPrinter(boolean ok, String message) {
        new Handler(Looper.getMainLooper()).post(() -> {
            Toast.makeText(this, message, Toast.LENGTH_LONG).show();
            if (webView != null) {
                String escaped = message.replace("\\", "\\\\").replace("'", "\\'");
                webView.evaluateJavascript("window.dispatchEvent(new CustomEvent('wg-printer-result',{detail:{ok:" + ok + ",message:'" + escaped + "'}}))", null);
            }
        });
    }

    @Override public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack(); else super.onBackPressed();
    }
    @Override protected void onDestroy() { if (webView != null) { webView.removeJavascriptInterface("WinGamesPrinter"); webView.destroy(); } super.onDestroy(); }
}
