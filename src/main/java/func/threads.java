package func;


import burp.Bfunc;
import burp.IHttpRequestResponse;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class threads implements Runnable {
    private Map<String, Object> zidian;
    private vulscan vul;
    private IHttpRequestResponse newHttpRequestResponse;
    private List<String> heads;
    private String pathRecord;

    public threads(Map<String, Object> zidian, vulscan vul, IHttpRequestResponse newHttpRequestResponse, List<String> heads, String pathRecord) {
        this.zidian = zidian;
        this.vul = vul;
        this.newHttpRequestResponse = newHttpRequestResponse;
        this.heads = heads;
        this.pathRecord = pathRecord;
    }

    @Override
    public void run() {
        go(this.zidian, this.vul, this.newHttpRequestResponse, this.heads, this.pathRecord);

    }

    private static void go(Map<String, Object> zidian, vulscan vul, IHttpRequestResponse newHttpRequestResponse, List<String> heads, String pathRecord) {

        String name = String.valueOf(zidian.get("name"));
        boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));
        String urll = Bfunc.ProcTemplateLanguag(String.valueOf(zidian.get("url")), newHttpRequestResponse, vul, false);
        String re = Bfunc.ProcTemplateLanguag(String.valueOf(zidian.get("re")), newHttpRequestResponse, vul, true);
        String info = String.valueOf(zidian.get("info"));
//        String state = (String) zidian.get("state");
        Collection<Integer> states = Bfunc.StatusCodeProc(String.valueOf(zidian.get("state")));

        if (loaded) {
            URL url = null;
            try {
                url = new URL(vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol(), vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost(), vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort(), String.valueOf(pathRecord) + urll);
            } catch (MalformedURLException e) {
                e.printStackTrace();
                return;
            }
//            boolean is_InList;
//            synchronized (vul.burp.history_url) {
//                is_InList = !vul.burp.history_url.contains(url.toString());
//            }
//            if (is_InList) {
//            synchronized (vul.burp.history_url) {
//                vul.burp.history_url.add(url.toString());
//            }
            byte[] request = vul.burp.help.buildHttpRequest(url);
            // 添加head
            if (vul.burp.Carry_head) {
                List<String> carryHeaders = new java.util.ArrayList<String>(heads);
                if (!carryHeaders.isEmpty()) {
                    carryHeaders.remove(0);
                }
                carryHeaders.add(0, vul.burp.help.analyzeRequest(request).getHeaders().get(0));
                request = vul.burp.help.buildHttpMessage(carryHeaders, new byte[]{});
            }
            if ("POST".equals(zidian.get("method"))) {
                request = vul.burp.help.toggleRequestMethod(request);
            }


            newHttpRequestResponse = vul.burp.call.makeHttpRequest(vul.httpService, request);


//                if (vul.burp.help.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == Integer.parseInt(state)) {

            if (newHttpRequestResponse.getResponse() == null){
                return;
            }

            if (states.contains(Integer.valueOf(vul.burp.help.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode()))) {
                byte[] resp = newHttpRequestResponse.getResponse();
                Pattern re_rule;
                try {
                    re_rule = Pattern.compile(re, Pattern.CASE_INSENSITIVE);
                } catch (PatternSyntaxException e) {
                    vul.burp.call.printError("Invalid regex in rule " + name + ": " + re);
                    return;
                }
                Matcher pipe = re_rule.matcher(vul.burp.help.bytesToString(resp));
                String lang = String.valueOf(vul.burp.help.bytesToString(resp).length());
                if (pipe.find()) {
                    synchronized(vul){
                        vulscan.ir_add(vul.burp.tags, name, vul.burp.help.analyzeRequest(newHttpRequestResponse).getMethod(), vul.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().toString(), String.valueOf(vul.burp.help.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode()) + " ", info, lang, newHttpRequestResponse);
                    }


                }
            }

            synchronized (vul.burp.call) {
                    vul.burp.call.printOutput(url.toString());
            }


//            } else {
////                vul.burp.call.printError("Skip: " + url.toString());
//            }

        }

    }


}
