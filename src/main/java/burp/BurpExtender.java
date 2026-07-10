package burp;

import UI.Tags;
import func.vulscan;
import utils.BurpAnalyzedRequest;
import utils.UrlRepeat;
import yaml.YamlUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory {

    public static final String CONFIG_DIR = System.getProperty("user.home") + File.separator + ".config" + File.separator + "RouteVulScan";
    public static String Yaml_Path = CONFIG_DIR + File.separator + "Config_yaml.yaml";
    public IBurpExtenderCallbacks call;
    public IExtensionHelpers help;
    public Tags tags;
    private UrlRepeat urlC;
    public Set<String> history_url = Collections.synchronizedSet(new LinkedHashSet<String>());
    public static String EXPAND_NAME = "Route Vulnerable Scan";
    public Config Config_l;
    public ThreadPoolExecutor ThreadPool;
    private ThreadPoolExecutor scanCoordinatorPool;
    private final Set<String> activeCoordinatorKeys = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
    private volatile int configuredThreadCount = 10;
    public boolean Carry_head = true;
    public boolean on_off = false;
    private static final int SCAN_COORDINATOR_QUEUE_LIMIT = 2000;

    public static String VERSION = "1.5.4";
    public Map<String, View> views;
    public JTextArea Host_textarea;




    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        YamlUtil.ensureYamlExists(Yaml_Path);
        this.call = callbacks;
        this.help = call.getHelpers();
        this.urlC = new UrlRepeat();
        this.Config_l = new Config(this);
        resizeThreadPool(10);
        getScanCoordinatorPool();
        this.tags = new Tags(callbacks, Config_l);
//        this.views = Bfunc.Get_Views();
        call.printOutput("@Info: Loading RouteVulScan success");
        call.printOutput("@Version: RouteVulScan " + VERSION);
        call.printOutput("@From: Code by F6JO");
        call.printOutput("@Github: https://github.com/F6JO/RouteVulScan");
        call.printOutput("");
        call.setExtensionName(EXPAND_NAME + " " + VERSION);
        call.registerScannerCheck(this);
        call.registerContextMenuFactory(this);


    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList<IScanIssue> IssueList = new ArrayList();
        if (on_off) {
            if (isHostAllowed(baseRequestResponse.getHttpService().getHost())) {
                IHttpService Http_Service = baseRequestResponse.getHttpService();
                String Root_Url = Http_Service.getProtocol() + "://" + Http_Service.getHost() + ":" + String.valueOf(Http_Service.getPort());
                try {
                    URL url = new URL(Root_Url + this.help.analyzeRequest(baseRequestResponse).getUrl().getPath());
                    BurpAnalyzedRequest Root_Request = new BurpAnalyzedRequest(this.call, baseRequestResponse);
                    String Root_Method = this.help.analyzeRequest(baseRequestResponse.getRequest()).getMethod();
                    String New_Url = this.urlC.RemoveUrlParameterValue(url.toString());
                    if (!this.urlC.addIfAbsent(Root_Method, New_Url)) {
                        return null;
                    }
                    submitRouteScan(Root_Request, null);
                    return IssueList;
                } catch (MalformedURLException e3) {
                    call.printError("RouteVulScan passive scan skipped malformed URL: " + e3.toString());
                    return IssueList;
                }
            } else {
                return IssueList;
            }


        } else {
            return IssueList;
        }
    }

    public synchronized ThreadPoolExecutor getThreadPool() {
        if (ThreadPool == null || ThreadPool.isShutdown() || ThreadPool.isTerminated()) {
            ThreadPool = createThreadPool(getConfiguredThreadCount());
        }
        return ThreadPool;
    }

    public synchronized Future<?> submitScanTask(Runnable task) {
        return getThreadPool().submit(task);
    }

    public boolean submitRouteScan(final BurpAnalyzedRequest rootRequest, final byte[] request) {
        if (rootRequest == null || rootRequest.requestResponse() == null) {
            return false;
        }
        String scanKey = "SCAN " + buildScanKey(rootRequest.requestResponse(), request);
        return submitCoordinatorTask(scanKey, new Runnable() {
            @Override
            public void run() {
                new vulscan(BurpExtender.this, rootRequest, request);
            }
        });
    }

    public boolean submitCoordinatorTask(final String key, final Runnable task) {
        if (task == null) {
            return false;
        }
        final String coordinatorKey = key == null || key.trim().length() == 0 ? UUID.randomUUID().toString() : key;
        if (!activeCoordinatorKeys.add(coordinatorKey)) {
            call.printError("Skip queued scan: " + coordinatorKey);
            return false;
        }
        try {
            getScanCoordinatorPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        task.run();
                    } catch (Throwable throwable) {
                        call.printError("RouteVulScan scan task failed: " + throwable.toString());
                    } finally {
                        activeCoordinatorKeys.remove(coordinatorKey);
                    }
                }
            });
            return true;
        } catch (RejectedExecutionException e) {
            activeCoordinatorKeys.remove(coordinatorKey);
            call.printError("RouteVulScan scan queue is full, skipped: " + coordinatorKey);
            return false;
        }
    }

    public String buildScanKey(IHttpRequestResponse requestResponse, byte[] request) {
        try {
            byte[] requestBytes = request == null ? requestResponse.getRequest() : request;
            IRequestInfo requestInfo = help.analyzeRequest(requestResponse.getHttpService(), requestBytes);
            return requestInfo.getMethod() + " " + urlC.RemoveUrlParameterValue(requestInfo.getUrl().toString());
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }

    public synchronized void resizeThreadPool(int size) {
        int normalizedSize = Math.max(1, Math.min(500, size));
        configuredThreadCount = normalizedSize;
        if (ThreadPool == null || ThreadPool.isShutdown() || ThreadPool.isTerminated()) {
            ThreadPool = createThreadPool(normalizedSize);
            return;
        }
        int currentMax = ThreadPool.getMaximumPoolSize();
        if (normalizedSize > currentMax) {
            ThreadPool.setMaximumPoolSize(normalizedSize);
            ThreadPool.setCorePoolSize(normalizedSize);
        } else {
            ThreadPool.setCorePoolSize(normalizedSize);
            ThreadPool.setMaximumPoolSize(normalizedSize);
        }
    }

    public int getConfiguredThreadCount() {
        if (Config_l == null) {
            return 10;
        }
        return Config_l.getThreadCount();
    }

    public synchronized void recreateThreadPoolAfterTimeout() {
        ThreadPoolExecutor oldPool = ThreadPool;
        ThreadPool = createThreadPool(configuredThreadCount);
        if (oldPool != null) {
            oldPool.shutdownNow();
        }
    }

    private ThreadPoolExecutor createThreadPool(int size) {
        return new ThreadPoolExecutor(size, size, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(), new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, "RouteVulScan-worker-" + counter.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    private synchronized ThreadPoolExecutor getScanCoordinatorPool() {
        if (scanCoordinatorPool == null || scanCoordinatorPool.isShutdown() || scanCoordinatorPool.isTerminated()) {
            scanCoordinatorPool = createScanCoordinatorPool();
        }
        return scanCoordinatorPool;
    }

    private ThreadPoolExecutor createScanCoordinatorPool() {
        return new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(SCAN_COORDINATOR_QUEUE_LIMIT), new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(1);

            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r, "RouteVulScan-scan-" + counter.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            }
        });
    }

    private boolean isHostAllowed(String host) {
        String text = Host_textarea == null ? "*" : Host_textarea.getText();
        String[] rows = text.split("\\R");
        boolean hasRule = false;
        for (String row : rows) {
            String rule = row.trim();
            if (rule.length() == 0 || rule.startsWith("#")) {
                continue;
            }
            hasRule = true;
            if ("*".equals(rule) || wildcardMatch(rule, host)) {
                return true;
            }
        }
        return !hasRule;
    }

    private boolean wildcardMatch(String rule, String host) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < rule.length(); i++) {
            char c = rule.charAt(i);
            if (c == '*') {
                regex.append(".*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        regex.append("$");
        Pattern pattern = Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(host);
        return matcher.matches();
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages == null || selectedMessages.length == 0) {
            return null;
        }
        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenuItem one_menu = new JMenuItem("Send To RouteVulScan");
        JMenuItem two_menu = new JMenuItem("Send To RouteVulScan and Head");
        one_menu.addActionListener(new Right_click_monitor(invocation, this));
        two_menu.addActionListener(new Right_click_monitor(invocation, this,true));
        menu.add(one_menu);
        menu.add(two_menu);


        return menu;
    }

    public void prompt(Component component,String message){
        if (component == null){
            component = this.tags.getUiComponent();
        }
        JOptionPane.showMessageDialog(component, message);
    }
}


class Right_click_monitor implements ActionListener {
    private IContextMenuInvocation invocation;
    private BurpExtender burp;

    private Boolean head;

    public Right_click_monitor(IContextMenuInvocation invocation, BurpExtender burp) {
        this.invocation = invocation;
        this.burp = burp;
        this.head = false;
    }

    public Right_click_monitor(IContextMenuInvocation invocation, BurpExtender burp, Boolean head) {
        this.invocation = invocation;
        this.burp = burp;
        this.head = head;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] RequestResponses = invocation.getSelectedMessages();
        if (RequestResponses == null || RequestResponses.length == 0) {
            return;
        }
        if (head) {
            JTextArea jTextArea = new JTextArea(1, 1);
            jTextArea.setLineWrap(false);
            List<String> headers = new ArrayList<String>(this.getHeaders(RequestResponses[0]));
            headers.remove(0);
            String headerText = "";
            for (String head : headers){
                headerText += head + "\n";
            }
            jTextArea.setText(headerText);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton ok = new JButton("OK");
            JButton cancel = new JButton("Cancel");
            buttonPanel.add(ok);
            buttonPanel.add(cancel);

            Window owner = burp.tags == null ? null : SwingUtilities.getWindowAncestor(burp.tags.getUiComponent());
            JDialog frame = new JDialog(owner, "Custom Request Header", Dialog.ModalityType.APPLICATION_MODAL);
            frame.getContentPane().setLayout(new BorderLayout(8, 8));
            frame.getContentPane().add(new JScrollPane(jTextArea), BorderLayout.CENTER);
            frame.getContentPane().add(buttonPanel, BorderLayout.SOUTH);
            frame.setMinimumSize(new Dimension(600, 400));
            frame.setSize(700, 500);
            frame.setLocationRelativeTo(owner);

            cancel.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    frame.dispose();
                }
            });
            ok.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    List<String> headersText = parseHead(jTextArea.getText());
                    if (headersText == null){
                        burp.prompt(frame,"Wrong header!");
                        return;
                    }
                    frame.dispose();
                    submitSelectedSiteMapScans(RequestResponses, headersText);
                }
            });
            frame.setVisible(true);

        }else {
            submitSelectedSiteMapScans(RequestResponses, null);
        }


    }

    private void submitSelectedSiteMapScans(IHttpRequestResponse[] requestResponses, final List<String> headersText) {
        Set<String> hostUrls = new LinkedHashSet<String>();
        for (IHttpRequestResponse requestResponse : requestResponses) {
            try {
                hostUrls.add(getSiteMapHostUrl(requestResponse));
            } catch (Exception exception) {
                burp.call.printError("RouteVulScan cannot read selected request: " + exception.toString());
            }
        }

        for (final String hostUrl : hostUrls) {
            final List<String> headerCopy = headersText == null ? null : new ArrayList<String>(headersText);
            String batchKey = "SITEMAP " + hostUrl + (headerCopy == null ? "" : " HEAD");
            burp.submitCoordinatorTask(batchKey, new Runnable() {
                @Override
                public void run() {
                    scanSiteMapHost(hostUrl, headerCopy);
                }
            });
        }
    }

    private String getSiteMapHostUrl(IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = burp.help.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        URL url = requestInfo.getUrl();
        String protocol = url.getProtocol();
        int port = url.getPort();
        if (port < 0) {
            port = requestResponse.getHttpService().getPort();
        }
        boolean defaultPort = ("http".equalsIgnoreCase(protocol) && port == 80) || ("https".equalsIgnoreCase(protocol) && port == 443);
        return protocol + "://" + url.getHost() + (defaultPort ? "" : ":" + port);
    }

    private void scanSiteMapHost(String hostUrl, List<String> headersText) {
        IHttpRequestResponse[] siteMapItems = burp.call.getSiteMap(hostUrl);
        if (siteMapItems == null || siteMapItems.length == 0) {
            burp.call.printError("RouteVulScan sitemap is empty: " + hostUrl);
            return;
        }

        Set<String> scanKeys = new LinkedHashSet<String>();
        int scanned = 0;
        int skipped = 0;
        for (IHttpRequestResponse siteMapItem : siteMapItems) {
            try {
                byte[] request = headersText == null ? null : replaceHeader(siteMapItem, headersText);
                String scanKey = burp.buildScanKey(siteMapItem, request);
                if (!scanKeys.add(scanKey)) {
                    skipped++;
                    continue;
                }
                BurpAnalyzedRequest rootRequest = new BurpAnalyzedRequest(burp.call, siteMapItem);
                new vulscan(burp, rootRequest, request);
                scanned++;
            } catch (Exception exception) {
                burp.call.printError("RouteVulScan sitemap item failed: " + exception.toString());
            }
        }
        burp.call.printOutput("RouteVulScan sitemap scan finished: " + hostUrl + ", scanned=" + scanned + ", skipped=" + skipped);
    }

    public byte[] replaceHeader(IHttpRequestResponse i, List<String> header) {
        List<String> headers = new ArrayList<>(header);

        IRequestInfo iRequestInfo = burp.help.analyzeRequest(i);
        iRequestInfo.getHeaders();
        headers.add(0, burp.help.analyzeRequest(i).getHeaders().get(0));

        return burp.help.buildHttpMessage(headers, new byte[]{});
    }

    public List<String> getHeaders(IHttpRequestResponse iHttpRequestResponse) {
        return this.burp.help.analyzeRequest(iHttpRequestResponse).getHeaders();
    }

    public static List<String> parseHead(String headerText) {
        if (headerText.equals("")) {
            return null;
        }
        List<String> rows = new ArrayList<>();
        for (String row : headerText.split("\n")) {
            if (!row.equals("")) {
                rows.add(row);
            }
        }
        if (rows.size() == 0) {
            return null;
        }
        return rows;
    }

}
