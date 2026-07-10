package func;

import UI.Tags;
import burp.*;
import utils.BurpAnalyzedRequest;
import yaml.YamlUtil;

import java.util.*;
import java.util.concurrent.Future;

public class vulscan {

    private IBurpExtenderCallbacks call;

    private BurpAnalyzedRequest Root_Request;

    private IExtensionHelpers help;
    public String Path_record;
    public BurpExtender burp;
    public IHttpService httpService;


    public vulscan(BurpExtender burp, BurpAnalyzedRequest Root_Request,byte[] request) {
        this.burp = burp;
        this.call = burp.call;
        this.help = burp.help;
        this.Root_Request = Root_Request;
        // 获取httpService对象
        if (request == null){
            request = this.Root_Request.requestResponse().getRequest();
        }
//        IRequestInfo iRequestInfo = help.analyzeRequest(request);
//        httpService = help.buildHttpService(iRequestInfo.getUrl().getHost(), iRequestInfo.getUrl().getPort(), iRequestInfo.getUrl().getProtocol());
        httpService = this.Root_Request.requestResponse().getHttpService();
        IRequestInfo analyze_Request = help.analyzeRequest(httpService, request);
        List<String> heads = new ArrayList<String>(analyze_Request.getHeaders());


        // 判断请求方法为POST
        if ("POST".equals(this.help.analyzeRequest(request).getMethod()))
            //将POST切换为GET请求
            request = this.help.toggleRequestMethod(request);
        // 获取所有参数
        IRequestInfo iRequestInfo = this.help.analyzeRequest(request);
        List<IParameter> Parameters = iRequestInfo.getParameters();
        // 判断参数列表不为空
        if (!Parameters.isEmpty())
            for (IParameter parameter : Parameters)
                // 删除所有参数
                request = this.help.removeParameter(request, parameter);

        // 创建新的请求类
//        IHttpRequestResponse newHttpRequestResponse = this.call.makeHttpRequest(httpService, request);
        IHttpRequestResponse newHttpRequestResponse = Root_Request.requestResponse();
        // 使用/分割路径
        IRequestInfo analyzeRequest = this.help.analyzeRequest(newHttpRequestResponse);
        String[] paths = analyzeRequest.getUrl().getPath().split("\\?",2)[0].split("/");

        Map<String, Object> Yaml_Map = YamlUtil.readYaml(burp.Config_l.yaml_path);
        Object loadList = Yaml_Map.get("Load_List");
        if (!(loadList instanceof List)) {
            this.burp.call.printError("RouteVulScan rule list is invalid.");
            return;
        }
        List<?> Listx = (List<?>) loadList;
        if (Listx == null || Listx.isEmpty()) {
            this.burp.call.printError("RouteVulScan rule list is empty.");
            return;
        }
        if (paths.length == 0) {
            paths = new String[]{""};
        }
        LaunchPath(paths,Listx,newHttpRequestResponse,heads);



    }

    private void LaunchPath(String[] paths,List<?> Listx,IHttpRequestResponse newHttpRequestResponse,List<String> heads){
        this.Path_record = "";
        for (String path : paths) {
            if (path.contains(".") && path.equals(paths[paths.length - 1])) {
                break;
            }
//            this.burp.call.printOutput(this.Path_record);

            if (!path.equals("")) {
                this.Path_record = this.Path_record + "/" + path;
            }

            String url = this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol() + "://" + this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost() + ":" + this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort() + String.valueOf(this.Path_record);

            boolean is_InList;
            synchronized (this.burp.history_url) {
                is_InList = this.burp.history_url.add(url);
            }

            if (is_InList) {
                List<Future<?>> futures = new ArrayList<Future<?>>();
                String pathRecord = this.Path_record;
                for (Object ruleObject : Listx) {
                    if (!(ruleObject instanceof Map)) {
                        continue;
                    }
                    Map<String, Object> zidian = (Map<String, Object>) ruleObject;
                    if (zidian == null || !Boolean.parseBoolean(String.valueOf(zidian.get("loaded")))) {
                        continue;
                    }
                    futures.add(this.burp.submitScanTask(new threads(zidian, this, newHttpRequestResponse, heads, pathRecord)));
                }


                long deadline = System.currentTimeMillis() + 31000L;
                boolean timeout = false;
                while (!allDone(futures)) {
                    if (System.currentTimeMillis() >= deadline) {
                        timeout = true;
                        for (Future<?> future : futures) {
                            if (!future.isDone()) {
                                future.cancel(true);
                            }
                        }
                        break;
                    }
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                if (timeout) {
                    this.burp.recreateThreadPoolAfterTimeout();
                    this.burp.call.printError("Timeout: " + url + "/*");
                }


            }else {
                this.burp.call.printError("Skip: " + url + "/*");
            }


        }
    }

    private boolean allDone(List<Future<?>> futures) {
        for (Future<?> future : futures) {
            if (!future.isDone()) {
                return false;
            }
        }
        return true;
    }


    public static void ir_add(Tags tag, String title, String method, String url, String StatusCode, String notes, String Size, IHttpRequestResponse newHttpRequestResponse) {
//        if (!tag.Get_URL_list().contains(url)) {
        tag.add(title, method, url, StatusCode, notes, Size, newHttpRequestResponse);
//        }
    }

}
