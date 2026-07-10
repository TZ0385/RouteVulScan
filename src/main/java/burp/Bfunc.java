package burp;


import func.vulscan;
import yaml.YamlUtil;

import javax.swing.*;
import java.util.*;
import java.util.regex.Pattern;

public class Bfunc {

    public static Map<String, View> Get_Views() {
        Map<String, View> views = new Hashtable<String, View>();
        Map<String, Object> jieguo = YamlUtil.readYaml(BurpExtender.Yaml_Path);
        List<Map<String, Object>> rule_list = (List<Map<String, Object>>) jieguo.get("Load_List");
        for (Map<String, Object> zidian : rule_list) {
            String type = (String) zidian.get("type");
            String id = String.valueOf(zidian.get("id"));
            String name = String.valueOf(zidian.get("name"));
            String url = String.valueOf(zidian.get("url"));
            String re = String.valueOf(zidian.get("re"));
            String info = String.valueOf(zidian.get("info"));
            String state = String.valueOf(zidian.get("state"));
            String method = String.valueOf(zidian.get("method"));
            boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));

            if (type == null || type.trim().length() == 0 || "null".equals(type)) {
                zidian.put("type", "default");
                YamlUtil.updateYaml(zidian, BurpExtender.Yaml_Path);
                type = "default";
            }

            if (views.containsKey(type)) {
                View view_one = views.get(type);
                view_one.log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                views.put(type, view_one);
            } else {
                View view_one = new View();
                view_one.log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                views.put(type, view_one);
            }
        }
        return views;

    }

    public static void show_yaml_view(BurpExtender burp, View view, String type) {
        if (view == null) {
            show_yaml(burp);
        } else {
            List<View.LogEntry> log = view.log;
            synchronized (log) {
                log.clear();
                Map<String, Object> Dict_Yaml = YamlUtil.readYaml(BurpExtender.Yaml_Path);
                List<Map<String, Object>> rule_list = (List<Map<String, Object>>) Dict_Yaml.get("Load_List");
                for (Map<String, Object> zidian : rule_list) {
                    String type2 = String.valueOf(zidian.get("type"));
                    if (type2.equals(type)) {
                        String id = String.valueOf(zidian.get("id"));
                        boolean loaded = Boolean.parseBoolean(String.valueOf(zidian.get("loaded")));
                        String name = String.valueOf(zidian.get("name"));
                        String url = String.valueOf(zidian.get("url"));
                        String re = String.valueOf(zidian.get("re"));
                        String info = String.valueOf(zidian.get("info"));
                        String state = String.valueOf(zidian.get("state"));
                        String method = String.valueOf(zidian.get("method"));
                        log.add(new View.LogEntry(id, type, loaded, name, method, url, re, info, state));
                    }
                }
                view.fireTableDataChanged();
            }
//            burp.views = Get_Views();
        }
    }

    public static void show_yaml(BurpExtender burp) {
        burp.views = Get_Views();
        burp.Config_l.ruleTabbedPane.removeAll();
        for (String key : burp.views.keySet()) {
            burp.Config_l.ruleTabbedPane.addTab(key, burp.views.get(key).Get_View());
        }
        burp.Config_l.ruleTabbedPane.addTab("...", new JLabel());


    }

    public static Collection<Integer> StatusCodeProc(String state){
        Collection<Integer> stateList = new ArrayList<Integer>();
        if (state == null || state.trim().length() == 0) {
            stateList.add(200);
            return stateList;
        }
        state = state.trim();
        if (state.length() != 3 && (state.contains(",") || state.contains("-"))){
            if (state.contains(",")){
                String[] states = state.split(",");
                for (String OneState:states){
                    OneState = OneState.trim();
                    if (OneState.contains("-")){
                        String[] parts = OneState.split("-");
                        if (parts.length == 2) {
                            try {
                                int start = Integer.parseInt(parts[0].trim());
                                int end = Integer.parseInt(parts[1].trim());
                                addStatusRange(stateList, start, end);
                            } catch (NumberFormatException ignored) {
                            }
                        }
                    }else if (OneState.length() == 3){
                        try {
                            addStatus(stateList, Integer.parseInt(OneState));
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
            }else if (state.contains("-")){
                String[] parts = state.split("-");
                if (parts.length == 2) {
                    try {
                        int start = Integer.parseInt(parts[0].trim());
                        int end = Integer.parseInt(parts[1].trim());
                        addStatusRange(stateList, start, end);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }else {
            try {
                addStatus(stateList, Integer.parseInt(state));
            } catch (NumberFormatException ignored) {
            }
        }
        if (stateList.isEmpty()) {
            stateList.add(200);
        }
        return stateList;

    }

    private static void addStatusRange(Collection<Integer> stateList, int start, int end) {
        int from = Math.max(100, start);
        int to = Math.min(599, end);
        if (from > to) {
            return;
        }
        for (int i = from; i <= to; i++) {
            stateList.add(i);
        }
    }

    private static void addStatus(Collection<Integer> stateList, int status) {
        if (status >= 100 && status <= 599) {
            stateList.add(status);
        }
    }



    public static String ProcTemplateLanguag(String url, IHttpRequestResponse HttpRequestResponse, vulscan vul,Boolean escape){

        if (url == null) {
            return "";
        }


        if (url.contains("{{") && url.contains("}}")){
            String marking = url.substring(url.indexOf("{{"), url.lastIndexOf("}}") + 2);
            String markingContent = marking.replace("{{", "").replace("}}", "").toLowerCase();
            String[] parts = markingContent.split("\\.");
            if (parts.length < 2) {
                return url;
            }
            IHttpService httpservice = HttpRequestResponse.getHttpService();
            switch (parts[0]){
                case "request":
                    IRequestInfo request = vul.burp.help.analyzeRequest(HttpRequestResponse);
                    switch (parts[1]){
                        case "head":
                            Map<String, String> heads = Bfunc.ProceHead(request.getHeaders());
                            if (parts.length < 3) {
                                return replaceOn(url,marking,"",escape);
                            }
                            if (parts[2].equals("host") && parts.length >3){
                                switch (parts[3]){
                                    case "main":
                                        return replaceOn(url,marking,Bfunc.AnalyHost(heads.get("host"),"main"),escape);
                                    case "name":
                                        return replaceOn(url,marking,Bfunc.AnalyHost(heads.get("host"),"name"),escape);
                                }
                            }
                            return replaceOn(url,marking,heads.get(parts[2]),escape);
                        case "method":
                            return replaceOn(url,marking,request.getMethod(),escape);
                        case "path":
                            String path = request.getUrl().getPath();
                            if (path == null) {
                                path = "";
                            }
                            return replaceOn(url,marking,path.startsWith("/") ? path.substring(1) : path,escape);
                        case "url":
                            return replaceOn(url,marking,request.getUrl().toString(),escape);
                        case "protocol":
                            return replaceOn(url,marking,httpservice.getProtocol(),escape);
                        case "port":
                            return replaceOn(url,marking,String.valueOf(httpservice.getPort()),escape);
                    }

                case "response":
                    byte[] xiangying = HttpRequestResponse.getResponse();
                    if (xiangying != null){
                        IResponseInfo response = vul.burp.help.analyzeResponse(xiangying);
                        switch (parts[1]){
                            case "head":
                                Map<String, String> heads = Bfunc.ProceHead(response.getHeaders());
                                if (parts.length < 3) {
                                    return replaceOn(url,marking,"",escape);
                                }
                                return replaceOn(url,marking,heads.get(parts[2]),escape);
                            case "status":
                                return replaceOn(url,marking,String.valueOf(response.getStatusCode()),escape);
                        }
                    }



            }

        }
            
            

        return url;
    }

    private static String replaceOn(String url,String one,String two,Boolean escape){
        if (two != null) {
            if (escape) {
                return url.replace(one, Pattern.quote(two));
            } else {
                return url.replace(one, two);
            }
        }
        return url.replace(one, "");
    }

    public static String AnalyHost(String host, String mode){
        if (host == null || host.trim().length() == 0) {
            return "";
        }
        String domain = host.split(":")[0];
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            return host;
        }
        String[] parts = domain.split("\\.");
        if (parts.length < 2) {
            return domain;
        }

        if (parts.length >= 3 && parts[parts.length-1].equals("cn") && parts[parts.length-2].equals("com")){
            if (mode.equals("main")){
                domain = parts[parts.length-3] + "." + parts[parts.length-2] + "." + parts[parts.length-1];
                return domain;
            }else if(mode.equals("name")){
                return parts[parts.length - 3];
            }

        }else {
            if (mode.equals("main")){
                domain = parts[parts.length-2] + "." + parts[parts.length-1];
                return  domain;
            }else if(mode.equals("name")){
                String lastPart = parts[parts.length - 1];
                return parts[parts.length - 2];
            }

        }
        return domain;
    }


    public static Map<String,String> ProceHead(List<String> heads){
        Map<String,String> headmap = new HashMap<String,String>();
        for (int i = 1; i < heads.size(); i++){
            String head = heads.get(i);
            if (!head.contains(":")) {
                continue;
            }
            String key = head.substring(0, head.indexOf(":")).toLowerCase();
            String value = head.substring(head.indexOf(":") + 1).trim();
            headmap.put(key,value);
        }
        return headmap;

    }



}
