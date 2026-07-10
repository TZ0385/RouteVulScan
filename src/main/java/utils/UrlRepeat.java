package utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UrlRepeat {
    private Map<String, Integer> MethodAndUrlMap = new ConcurrentHashMap<String, Integer>();

    public Map<String, Integer> getRequestMethodAndUrlMap() {
        return this.MethodAndUrlMap;
    }

    public void addMethodAndUrl(String Method, String url) {
        if (Method == null || Method.length() <= 0)
            throw new IllegalArgumentException("Request method cannot be empty");
        if (url == null || url.length() <= 0)
            throw new IllegalArgumentException("Url cannot be empty");
        getRequestMethodAndUrlMap().put(String.valueOf(Method) + " " + url, Integer.valueOf(1));
    }

//    public void delMethodAndUrl(String Method, String url) {
//        if (Method != null && Method.length() > 0 && url != null && url.length() > 0)
//            getRequestMethodAndUrlMap().remove(String.valueOf(Method) + " " + url);
//    }

    public boolean check(String Method, String url) {
        if (getRequestMethodAndUrlMap().get(String.valueOf(Method) + " " + url) != null)
            return true;
        return false;
    }

    public boolean addIfAbsent(String Method, String url) {
        if (Method == null || Method.length() <= 0)
            throw new IllegalArgumentException("Request method cannot be empty");
        if (url == null || url.length() <= 0)
            throw new IllegalArgumentException("Url cannot be empty");
        return getRequestMethodAndUrlMap().putIfAbsent(String.valueOf(Method) + " " + url, Integer.valueOf(1)) == null;
    }

    public String RemoveUrlParameterValue(String url) {
        try {
            URL parsedUrl = new URL(url);
            String urlQuery = parsedUrl.getQuery();
            if (urlQuery == null) {
                return url;
            }
            int queryStart = url.indexOf('?');
            if (queryStart < 0) {
                return url;
            }
            int fragmentStart = url.indexOf('#', queryStart);
            String fragment = fragmentStart >= 0 ? url.substring(fragmentStart) : "";
            return url.substring(0, queryStart + 1) + RemoveParameterValue(urlQuery) + fragment;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private String RemoveParameterValue(String urlQuery) {
        if (urlQuery == null || urlQuery.length() == 0) {
            return "";
        }
        String parameter = "";
        String[] split = urlQuery.split("&");
        for (int i = 0; i < split.length; i++)
            parameter = String.valueOf(parameter) + split[i].split("=")[0] + "=&";
        return parameter.substring(0, parameter.length() - 1);
    }
}
