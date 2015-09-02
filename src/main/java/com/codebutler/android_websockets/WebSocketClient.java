package com.codebutler.android_websockets;

import android.os.Handler;
import android.os.HandlerThread;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class WebSocketClient {
    private static final String TAG = "WebSocketClient";
    private final static int SC_SWITCHING_PROTOCOLS = 101;
    private static TrustManager[] sTrustManagers;
    private final Object mSendLock = new Object();
    private URI mURI;
    private Listener mListener;
    private Socket mSocket;
    private Thread mThread;
    private HandlerThread mHandlerThread;
    private Handler mHandler;
    private List<Header> mExtraHeaders;
    private HybiParser mParser;


    private WebSocketClient(URI uri, Listener listener, List<Header> extraHeaders) {
        mURI = uri;
        mListener = listener;
        mExtraHeaders = extraHeaders;
        mParser = new HybiParser(this);

        mHandlerThread = new HandlerThread("websocket-thread");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());
    }

    public static void setTrustManagers(TrustManager[] tm) {
        sTrustManagers = tm;
    }

    public Listener getListener() {
        return mListener;
    }

    public void connect() {
        if (mThread != null && mThread.isAlive()) {
            return;
        }

        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String secret = createSecret();

                    int port = (mURI.getPort() != -1) ? mURI.getPort() : (mURI.getScheme().equals("wss") ? 443 : 80);

                    String path = TextUtils.isEmpty(mURI.getPath()) ? "/" : mURI.getPath();
                    if (!TextUtils.isEmpty(mURI.getQuery())) {
                        path += "?" + mURI.getQuery();
                    }

                    String originScheme = mURI.getScheme().equals("wss") ? "https" : "http";
                    URI origin = new URI(originScheme, "//" + mURI.getHost(), null);

                    SocketFactory factory = mURI.getScheme().equals("wss") ? getSSLSocketFactory() : SocketFactory.getDefault();
                    mSocket = factory.createSocket(mURI.getHost(), port);

                    PrintWriter out = new PrintWriter(mSocket.getOutputStream());
                    out.print("GET " + path + " HTTP/1.1\r\n");
                    out.print("Upgrade: websocket\r\n");
                    out.print("Connection: Upgrade\r\n");
                    out.print("Host: " + mURI.getHost() + "\r\n");
                    out.print("Origin: " + origin.toString() + "\r\n");
                    out.print("Sec-WebSocket-Key: " + secret + "\r\n");
                    out.print("Sec-WebSocket-Version: 13\r\n");
                    if (mExtraHeaders != null) {
                        for (Header pair : mExtraHeaders) {
                            out.print(String.format("%s: %s\r\n", pair.getName(), pair.getValue()));
                        }
                    }
                    out.print("\r\n");
                    out.flush();

                    HybiParser.HappyDataInputStream stream = new HybiParser.HappyDataInputStream(mSocket.getInputStream());

                    // Read HTTP response status line.
                    StatusLine statusLine = parseStatusLine(readLine(stream));
                    if (statusLine == null) {
                        throw new Exception("Received no reply from server.");
                    } else if (statusLine.getCode() != SC_SWITCHING_PROTOCOLS) {
                        throw new IOException(statusLine.getCode() + " " + statusLine.getMessage());
                    }

                    // Read HTTP response headers.
                    String line;
                    boolean validated = false;

                    while (!TextUtils.isEmpty(line = readLine(stream))) {
                        Header header = parseHeader(line);
                        if (header.getName().equals("Sec-WebSocket-Accept")) {
                            String expected = createSecretValidation(secret);
                            String actual = header.getValue().trim();

                            if (!expected.equals(actual)) {
                                throw new Exception("Bad Sec-WebSocket-Accept header value.");
                            }

                            validated = true;
                        }
                    }

                    if (!validated) {
                        throw new Exception("No Sec-WebSocket-Accept header.");
                    }

                    mListener.onConnect();

                    // Now decode websocket frames.
                    mParser.start(stream);

                } catch (EOFException ex) {
                    Log.d(TAG, "WebSocket EOF!", ex);
                    mListener.onDisconnect(0, "EOF");

                } catch (SSLException ex) {
                    // Connection reset by peer
                    Log.d(TAG, "Websocket SSL error!", ex);
                    mListener.onDisconnect(0, "SSL");

                } catch (Exception ex) {
                    mListener.onError(ex);
                }
            }
        });
        mThread.start();
    }

    public void disconnect() {
        if (mSocket != null) {
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        mSocket.close();
                        mSocket = null;
                    } catch (IOException ex) {
                        Log.d(TAG, "Error while disconnecting", ex);
                        mListener.onError(ex);
                    }
                }
            });
        }
    }

    public void send(String data) {
        sendFrame(mParser.frame(data));
    }

    public void send(byte[] data) {
        sendFrame(mParser.frame(data));
    }

    private StatusLine parseStatusLine(String line) {
        if (TextUtils.isEmpty(line)) {
            return null;
        }
        String[] tokens = line.split(" ");

        if (tokens.length < 3 || !tokens[0].startsWith("HTTP/1.")) {
            return null;
        }

        int code = Integer.valueOf(tokens[1]);

        StringBuilder messageBuilder = new StringBuilder();

        for (int i = 2; i < tokens.length; i++) {
            messageBuilder.append(tokens[i]);
            messageBuilder.append(' ');
        }

        messageBuilder.deleteCharAt(messageBuilder.length() - 1);

        return new StatusLine(messageBuilder.toString(), code);
    }

    private Header parseHeader(String line) {
        if (TextUtils.isEmpty(line)) {
            return null;
        }

        String[] tokens = line.split(":");

        if (tokens.length < 2) {
            return null;
        }

        return new Header(tokens[0], tokens[1]);
    }

    // Can't use BufferedReader because it buffers past the HTTP data.
    private String readLine(HybiParser.HappyDataInputStream reader) throws IOException {
        int readChar = reader.read();
        if (readChar == -1) {
            return null;
        }
        StringBuilder string = new StringBuilder("");
        while (readChar != '\n') {
            if (readChar != '\r') {
                string.append((char) readChar);
            }

            readChar = reader.read();
            if (readChar == -1) {
                return null;
            }
        }
        return string.toString();
    }

    private String createSecret() {
        byte[] nonce = new byte[16];
        for (int i = 0; i < 16; i++) {
            nonce[i] = (byte) (Math.random() * 256);
        }
        return Base64.encodeToString(nonce, Base64.DEFAULT).trim();
    }

    private String createSecretValidation(String secret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update((secret + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes());
            return Base64.encodeToString(md.digest(), Base64.DEFAULT).trim();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    void sendFrame(final byte[] frame) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    synchronized (mSendLock) {
                        if (mSocket == null) {
                            throw new IllegalStateException("Socket not connected");
                        }
                        OutputStream outputStream = mSocket.getOutputStream();
                        outputStream.write(frame);
                        outputStream.flush();
                    }
                } catch (IOException e) {
                    mListener.onError(e);
                }
            }
        });
    }

    private SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, sTrustManagers, null);
        return context.getSocketFactory();
    }

    public interface Listener {
        void onConnect();

        void onMessage(String message);

        void onMessage(byte[] data);

        void onDisconnect(int code, String reason);

        void onError(Exception error);
    }

    public static final class Builder {
        private List<Header> headers = new ArrayList<>();

        private URI uri;

        private Listener listener;


        public Builder endPoint(String endPoint) {

            URI u = URI.create(endPoint);

            String scheme = u.getScheme();

            if (scheme.equals("http")) {
                scheme = "ws";
            }

            if (scheme.equals("https")) {
                scheme = "wss";
            }

            try {
                uri = new URI(scheme,
                        u.getUserInfo(), u.getHost(), u.getPort(),
                        u.getPath(), u.getQuery(),
                        u.getFragment());
            } catch (URISyntaxException e) {
                uri = null;
            }

            return this;
        }

        public Builder listener(Listener listener) {
            this.listener = listener;
            return this;
        }


        public Builder addHeader(Header header) {
            headers.add(header);
            return this;
        }

        public Builder addHeaders(List<Header> headers) {
            this.headers.addAll(headers);
            return this;
        }

        public Builder addHeader(String name, String value) {
            this.headers.add(new Header(name, value));
            return this;
        }

        public WebSocketClient build() {
            if (uri == null) {
                throw new IllegalArgumentException("Endpoint url must be provided");
            }

            if (listener == null) {
                throw new IllegalArgumentException("Websocket listener must be provided");
            }
            return new WebSocketClient(uri, listener, headers);

        }


    }

}