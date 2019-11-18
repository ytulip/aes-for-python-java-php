import com.alibaba.fastjson.JSONObject;
import sun.net.www.http.HttpClient;
import utils.Crypt;
import utils.SHA1;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lishidong on 2018/10/19.
 */
public class Test{

    public static void main(String[] args) throws Exception {
        String encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        Crypt crypt = new Crypt(encodingAesKey);
        String encryptStr = crypt.encrypt("i will pick you up");
        System.out.println("密文:");
        System.out.println(encryptStr);

        /*签名*/
        String timestamp = Long.toString(System.currentTimeMillis());
        String nonce = crypt.getRandomStr(6);
        String signature = SHA1.getSHA1(encodingAesKey, timestamp, nonce, encryptStr);
        System.out.println("签名:");
        System.out.println(signature);


        JSONObject jsonObject = new JSONObject();
        jsonObject.put("data", encryptStr);
        jsonObject.put("timestamp", timestamp);
        jsonObject.put("nonce", nonce);
        jsonObject.put("signature", signature);


        String response = sendPostRequest("http://127.0.0.1:8009/bor/aes_test",jsonObject);
        System.out.println("请求返回:");
        System.out.println(response);

        /*验签*/
        //先转成json对象
        com.alibaba.fastjson.JSONObject resjsonObject = com.alibaba.fastjson.JSONObject.parseObject(response);
        //再获取里面的message对应的值
        String resData = resjsonObject.get("data").toString();
        String resTimestamp = resjsonObject.get("timestamp").toString();
        String resNonce = resjsonObject.get("nonce").toString();
        String resSignature = resjsonObject.get("signature").toString();

        String checkSignature = SHA1.getSHA1(encodingAesKey, resTimestamp, resNonce, resData);
        System.out.println(checkSignature);
        if( checkSignature.equals(resSignature) )
        {
            System.out.println("验签成功");
        } else
        {
            System.out.println("验签失败");
            return;
        }

        String decryptStr = crypt.decrypt(resData);
        System.out.println("解密:");
        System.out.println(decryptStr);
    }


    public static String sendPostRequest(String url, JSONObject params){
        HttpURLConnection httpURLConnection = null;
        OutputStream out = null; //写
        InputStream in = null;   //读
        int responseCode = 0;    //远程主机响应的HTTP状态码
        String result="";
        try{
            StringBuilder postData = new StringBuilder();
            byte[] postDataBytes =JSONObject.toJSONString(params).getBytes("UTF-8");

            URL sendUrl = new URL(url);
            httpURLConnection = (HttpURLConnection)sendUrl.openConnection();
            //post方式请求
            httpURLConnection.setRequestMethod("POST");
            //设置头部信息
            httpURLConnection.setRequestProperty("headerdata", "ceshiyongde");
            //一定要设置 Content-Type 要不然服务端接收不到参数
            httpURLConnection.setRequestProperty("Content-Type", "application/json");
//            httpURLConnection.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
            //指示应用程序要将数据写入URL连接,其值默认为false（是否传参）
            httpURLConnection.setDoOutput(true);
            //httpURLConnection.setDoInput(true);

            httpURLConnection.setUseCaches(false);
            httpURLConnection.setConnectTimeout(30000); //30秒连接超时
            httpURLConnection.setReadTimeout(30000);    //30秒读取超时
            //获取输出流
            out = httpURLConnection.getOutputStream();
            //输出流里写入POST参数
            out.write(postDataBytes);
            out.flush();
            out.close();
            responseCode = httpURLConnection.getResponseCode();
            BufferedReader br = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream(),"UTF-8"));
            result =br.readLine();
        }catch(Exception e) {
            e.printStackTrace();

        }
        return result;
    }
}
