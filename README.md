![image](https://github.com/shanshanerxi/Memory-horse/assets/126464165/7d39f92a-5765-4042-9f70-414818ef44d2)
![image](https://github.com/shanshanerxi/Memory-horse/assets/126464165/cfea6a9d-a2fb-4561-9573-78b355256089)

# 捉妖记：内存马的现形术与封印大法

### 内存马原理

   本质是：携带恶意木马在内存中运行的web组件，不同语言的内存马不能通用，因为容器各有不同，一个容器包含多种组件，组件多样性导致了内存马的多样性

**内存马特性：**

- 隐蔽性强：由于不存在于硬盘上，常规的文件系统检查无法发现内存马

- 实时性：内存马一旦植入，便可在系统启动时自动加载，无需等待文件系统挂载

- 依赖性：内存马通常依赖于特定的系统漏洞或配置错误，一旦修复这些漏洞，内存马就失效

  

### C/S请求方式

根据C/S请求方式，当浏览器发送请求到服务器时，如在Tomcat容器中，请求的处理流程  监听——过滤——处理回应：

- **Listener（监听器）**：监听不同的事件并执行相应的回调函数  列如

  ```
  1.ServletContextListener：
  	contextInitialized(ServletContextEvent): 当Servlet上下文（Web应用）初始化完成后触发通常用于执行应用启动时的一次		性设置，如加载配置文件、初始化数据库连接池
  	contextDestroyed(ServletContextEvent): 当Servlet上下文即将销毁前触发用于执行清理工作，如关闭数据库连接、释放资		源、记录日志
  	
  2.HttpSessionListener：
  	sessionCreated(HttpSessionEvent): 当一个新的HTTP会话被创建时触发可以用来跟踪会话创建、初始化会话属性
  	sessionDestroyed(HttpSessionEvent): 当一个HTTP会话结束时触发可以用于记录会话结束信息、清理与会话相关的资源
  
  3.ServletRequestListener：
  	requestInitialized(ServletRequestEvent): 当一个ServletRequest被创建时触发可以用来记录请求的开始、初始化请求级		别的资源
  	requestDestroyed(ServletRequestEvent): 当一个ServletRequest结束时触发可以用于记录请求的结束、清理请求级别的资源		
  ```

- **Filter（过滤器）**：对请求进行预处理，如权限检查、日志记录、请求内容修改等，也可以在响应发送前进行后处理

- **Servlet**：最终处理客户端的请求并生成响应内容，如动态生成网页或提供RESTful服务

  ![](D:\OneDrive\图片\本机照片\image-20240423172645956.png)

**示例**

1. ServletContextListener

假设我们想要在Web应用启动和关闭时记录日志

```java
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.logging.Logger;

public class MyContextListener implements ServletContextListener {
    // 创建一个Logger实例用于记录日志
    private static final Logger logger = Logger.getLogger(MyContextListener.class.getName());

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        // 当Web应用启动，ServletContext被初始化后调用此方法
        logger.info("Web application started.");
        // 在这里执行应用启动时的初始化操作，如数据库连接、加载配置等
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // 当Web应用停止，ServletContext被销毁前调用此方法
        logger.info("Web application is stopping. Cleaning up resources.");
        // 在这里执行清理操作，如关闭数据库连接、释放资源等
    }
}
```

2. Filter 

我们创建一个Filter，用于记录请求日志、检查权限以及修改请求内容

```java
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.logging.Logger;

public class ExampleFilter implements Filter {
    // 使用java.util.logging进行日志记录
    private static final Logger logger = Logger.getLogger(ExampleFilter.class.getName());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Filter初始化时执行的操作，例如获取过滤条件的配置
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // 记录请求日志
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        logger.info("Received request for URI: " + httpRequest.getRequestURI());

        // 权限检查：这里简单地检查请求是否有特定的参数，以决定是否放行
        String authParam = httpRequest.getParameter("auth");
        if (authParam == null || !authParam.equals("valid_token")) {
            logger.warning("Unauthorized access attempt");
            // 如果权限检查失败，可以写入错误响应或转发到登录页面
            response.getWriter().write("Unauthorized access. Please provide a valid token.");
            return;
        }

        // 修改请求内容：在请求传递给下一个Filter或Servlet之前，可以修改请求对象
        // 例如，可以添加一些请求属性或者修改请求参数
        // request.setAttribute("someAttribute", "value");

        // 继续过滤器链，请求将传递给下一个过滤器或Servlet
        chain.doFilter(request, response);

        // 响应后处理：可以修改响应的内容，但请注意，修改响应内容会影响客户端的行为
        // ServletResponse httpResponse = (ServletResponse) response;
        // 响应内容修改示例（不推荐在实际应用中修改响应实体）:
        // PrintWriter writer = response.getWriter();
        // writer.write("<br>This is an additional message added by the filter.");
    }

    @Override
    public void destroy() {
        // Filter销毁时执行的操作
    }
}
```

3. Servlet 示例

实现了一个基本的RESTful服务，用于响应HTTP GET请求，并返回一个简单的JSON格式的响应消息

```java
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;
import org.json.JSONObject;

public class ExampleServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // 设置响应的内容类型为 JSON
        response.setContentType("application/json");
        
        // 创建一个JSON对象，用于存放响应数据
        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("message", "Hello, World!");
        jsonResponse.put("status", "success");

        // 使用PrintWriter将JSON响应写入客户端
        try (PrintWriter out = response.getWriter()) {
            out.print(jsonResponse.toString());
        }
    }

    // 可以添加更多的doPost, doPut, doDelete等方法来处理不同类型的HTTP请求
}
```

在`web.xml`中配置Filter和Servlet，或者使用注解来自动注册它们，使用注解的方式，你只需要在Listener和Servlet类上使用`@WebListener`和`@WebServlet`注解，Tomcat会在启动时自动注册它们

请求处理流程

当一个HTTP请求发送到服务器并请求一个资源时，Tomcat容器将执行以下步骤：

1. **Listener**：如果有ServletContextListener监听器，它将首先检测到Web应用的启动或停止，并执行相应的回调函数

2. **Filter**：请求到达Filter，在这里可以检查或修改请求和响应如果Filter链中有多个Filter，它们将按照配置的顺序被调用

3. **Servlet**：请求最后到达Servlet，Servlet处理请求并生成响应，然后返回给客户端

**请求在到达对应的Servlet之前，会依次经过Listener、Filter等组件每个组件都可以对请求进行处理，但它们的作用和处理的阶段是不同的Listener更多关注于应用生命周期和请求生命周期的事件，而Filter则侧重于请求内容的过滤和修改最终，请求到达Servlet，由Servlet生成响应并返回给客户端**



那么根据内存马的原理和C/S的请求方式，内存马的植入便有了两种方式



###  **内存马植入方式**

​	1.基于容器组件来实现，被修改后其带恶意功能,修改掉组件，执行了恶意功能又返回

​	2.将容器调用链中，向其新增自己的恶意组件，比如  监听器-过滤器-响应器  变为 监听器-过滤器-恶意响应器—响应器

​	3.漏洞注入内存马 利用服务器上的安全漏洞

​	4.API注入内存马 滥用或误用应用程序提供的API接口，通过它们上传或执行恶意代码，从而在服务器内存中植入后门或木马程序



总结：在调用链（多个组件配合完成交互操作，思考你上京东买东西的时候，前端创建订单，后端接受处理 所以为调用链）对其中某个服务进行修改并且实列化映射便完成了内存马的注入，因为在Web应用程序中，组件（如servlet、filter等）和URL之间的映射关系通常在web.xml文件中定义这种映射关系使得服务器能够根据请求的URL找到并调用相应的组件在服务器启动时，它会读取web.xml文件，解析其中的配置信息，并根据这些信息初始化相应的组件，这个过程被称为实例化，内存马利用这个机制来实现 例如，它会修改web.xml文件，添加一些恶意的组件和URL映射关系当服务器启动并读取web.xml文件时，这些恶意的组件就会被实例化并运行，其他的则通过利用服务器的漏洞/配置错误,滥用API接口,内存马可以根据不同的环境和条件采取不同的注入方,但我认为 目前这四种方式是最常见的



**同样基于内存马的植入方式，内存马便有了不同种类的划分，而不同语言对应的容器不同，服务不同，所以内存马也不同**



### 不同语言的内存马

#### Java内存马

1. 特征：

   - 隐藏性：利用Java的内存管理机制来隐藏自身，通过动态代理、类加载器（Class Loader）来动态加载恶意代码，使得代码在运行时才被编译和加载，增加了检测难度，利用Java的反射机制来动态调用方法

   - 内存驻留：Java内存马会在JVM的内存空间中长期驻留，不进行任何文件级别的持久化存储这意味着即使没有明显的文件痕迹，恶意代码仍然可以在内存中持续运行

     

2. 检测：

   - 1.排查web xml注册表里面找未知的过滤器,本地自创的filer，2.找到特殊的类加载器 分析是否包含恶意代码     3.本地不存在的类文件 没有对应的类
   - 堆dump分析：通过分析Java堆内存dump文件，寻找可疑的对象实例和类加载器，发现隐藏的恶意代码和异常的对象引用关系
   - 监控工具：使用Java Profiler（如VisualVM或JProfiler）来监控应用的内存使用和类加载行为，寻找异常模式这些工具可以提供实时的性能数据和内存快照，帮助定位问题
   - 安全审计：实施安全审计，记录和分析系统调用、网络通信和异常行为
   - 日志分析：分析应用日志和系统日志，寻找异常消息，如异常堆栈跟踪、未授权的系统调用

3. 工具：

   - JConsole：JConsole是Java自带的监控工具，可以监控Java进程的内存使用、线程活动和类加载情况它提供了一个图形界面，方便开发者实时查看和调试Java应用
   - MAT（Memory Analyzer Tool）：MAT是一个强大的Java堆内存分析工具，可以帮助找出内存泄漏和内存占用高的原因它可以分析堆dump文件，提供详细的内存使用报告和对象引用图
   - Java Mission Control：这是一套高级的Java性能分析工具，可以帮助开发者定位内存问题和其他性能瓶颈它提供了丰富的监控视图和诊断功能，适用于生产环境和开发环境



#### **PHP不死马**：

1. 特征：自我删除进入内存死循环繁殖的木马 不断回连的URL
1. 检测：1.利用不同线程/进程对共享资源的访问条件竞争，2.文件完整性检查  3.异常的PHP进程
1. 工具：Valgrind内存性能分析工具来查找异常的内存分配和释放模式

```php
<?php
// PHP不死马示例，使用计划任务保证持久性
echo "Starting the persistent PHP script.\n";

// 尝试执行一个恶意操作
echo "Performing malicious activity...\n";

// 计划任务：每天执行一次自身
$crontab = `crontab -l`;
if (!strpos($crontab, __FILE__)) {
    echo "Scheduling the script to run daily...\n";
    system("(crontab -l 2>&1; echo '0 0 * * * php " . __FILE__ . " > /dev/null 2>&1 &') | crontab");
}

// 自我删除，但计划任务会每天重启它
echo "Removing the script file...\n";
unlink(__FILE__);
?>
```



#### **C/C++内存马**：

1. 特征使用`dlopen()`函数加载恶意共享库的自定义加载机制，通过`system()`、`popen()`等方式执行系统命令，使用`fork()`创建子进程并在后台运行以隐藏恶意活动，以及使用`malloc()`、`calloc()`或`realloc()`进行异常内存分配或重分配
1. 检测：由于这类内存马通常更隐蔽，使用诸如`strace`、`ltrace`、`Valgrind`等通用的系统监控和内存调试工具来辅助分析

```cpp
#include <iostream>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    // 加载恶意共享库
    void* handle = dlopen("./malicious_library.so", RTLD_LAZY);
    if (!handle) {
        std::cerr << "Error loading library: " << dlerror() << std::endl;
        return EXIT_FAILURE;
    }

    // 找到并执行恶意函数
    typedef void (*malicious_func_t)();
    malicious_func_t malicious_func = (malicious_func_t)dlsym(handle, "malicious_function");
    if (malicious_func) {
        malicious_func();
    }

    // 创建一个隐藏的子进程
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程继续执行恶意活动
        while (true) {
            // 恶意活动...
            sleep(3600); // 每小时醒来一次
        }
    }

    // 父进程退出
    return EXIT_SUCCESS;
}
```

#### Python内存马

1. 利用flask框架中存在的ssti注入来实现内存修改的,特征使用`importlib`或自定义的`__import__`操作来加载恶意模块，使用`threading`或`multiprocessing`库创建持久化的线程或进程，通过全局解释器锁（GIL）和其他内存分配策略来操纵内存，以及通过HTTP请求或其他通信手段向攻击者反馈系统状态,,
1. 检测：使用`pyarmor对Python源代码进行加密，以防止未授权的使用和逆向工程`这样的工具来检测和防止恶意代码的执行

```python
import os
import threading
import importlib.util

def malicious_activity():
    while True:
        # 执行恶意操作，例如：发送数据到远程服务器
        pass

def load_malicious_module():
    # 动态加载恶意模块
    spec = importlib.util.spec_from_file_location("malicious_module", "/path/to/malicious_module.py")
    malicious_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(malicious_module)

    # 创建一个守护线程以保持恶意活动
    thread = threading.Thread(target=malicious_activity, daemon=True)
    thread.start()

if __name__ == "__main__":
    load_malicious_module()
    # 尝试自我删除
    os.remove(__file__)
```



#### .NET内存马

1. 特征：通过反射或自定义的程序集加载逻辑来加载恶意代码，与远程服务器建立持久连接并进行隐秘的数据交换，使用代码混淆技术使恶意代码难以被反编译或分析，以及在应用程序的生命周期中绑定到特定事件的恶意操作
1. 检测：使用`.NET Reflector`这样的反编译工具来分析和理解.NET应用程序的执行流程，帮助检测潜在的恶意行为

```csharp
using System;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;

class MaliciousAssembly {
    static void Main() {
        // 使用AssemblyLoadContext加载恶意程序集以避免被发现
        AssemblyLoadContext context = new AssemblyLoadContext("MaliciousAssemblyContext", isCollectible: true);
        Assembly assembly = context.LoadFromAssemblyPath("malicious_assembly.dll");

        // 获取并执行恶意类型和方法
        var type = assembly.GetType("MaliciousNamespace.MaliciousType");
        var method = type.GetMethod("MaliciousMethod", BindingFlags.NonPublic | BindingFlags.Static);
        method.Invoke(null, null);

        // 创建一个长时间运行的线程
        Thread thread = new Thread(() => {
            // 恶意线程活动
            while (true) {
                // 执行恶意操作，例如：监听网络请求
            }
        });
        thread.IsBackground = true;
        thread.Start();

        // 尝试自我删除
        AssemblyLoadContext.Unload(context);
    }
}
```





### **不同容器的内存马**

#### Tomcat内存马

Tomcat的请求处理流程可以被用来植入内存马

- **Listener**：监听器可以监听各种应用、会话和请求事件
- **Filter**：过滤器可以拦截请求和响应，进行预处理或后处理
- **Servlet**：Servlet是Java Web应用的基础组件，用于处理客户端请求

- **Valve**：Tomcat的Valve可以看作是全局过滤器，用于访问控制、日志记录等
- **Executor**：Tomcat的线程池，可以用于控制应用的并发处理
- **Websocket**：支持WebSocket协议，可以用于实现全双工通信

**API**：

- **JavaAgent**：利用Java Agent技术，可以在JVM启动时注入和执行Java字节码

  

#### Weblogic内存马

Weblogic的组件

- **Listener**：与Tomcat类似，监听器可以响应各种事件
- **Servlet**：处理HTTP请求的Java组件

- **Websocket**：与Tomcat的WebSocket类似，用于实现全双工通信

**API**：

- **JavaAgent**：与Tomcat中的使用类似，可以在JVM层面进行操作

  

#### Spring Boot内存马

Spring Boot特有的组件

- **Controller**：Spring MVC中的控制器，用于处理HTTP请求
- **Interceptor**：拦截器可以拦截Controller的调用，进行前置或后置处理

**API**：

- **JavaAgent**：同样，可以在JVM启动时通过Java Agent注入代码

  

  

#### **JBoss/WildFly**

JBoss的微内核、服务和部署器可以被利用来植入内存马

- API接：通过JMX（Java Management Extensions）和JPA（Java Persistence API）接口进行操作

  

- #### **Docker容器**：

  - 通过Docker的API和容器逃逸技术，可以在宿主机上执行恶意命令

  - API：利用Docker的远程API进行攻击

    

- #### **Kubernetes**：

  利用Kubernetes的Pods、Deployments资源和控制器

  - API：通过Kubernetes API进行集群内的横向移动和权限提升



**由此可以看出不同语言和不同容器的内存马是不一样的，但从哲学万物归源的角度上来说，内存马归根结底可以分为 数据结构型和API型，混合型，内核型**



### **内存马种类划分**

![](D:\OneDrive\图片\本机照片\微信图片_20240423195021.png)

#### 数据结构型

数据结构性:利用内存中数据结构来存储和执行恶意代码的后门程序，直接在内存中修改数据，从而绕过一些安全检查，不依赖具体的API，所以更加灵活，可以适用于更多的环境和场景,但要求对目标系统的内存结构和数据布局有深入的了解，而组件则通过操作数据结构实现特定功能（数据库管理系统会使用树状结构来维护索引，或者使用哈希表来加速查找操作）攻击者则利用组件的特性造成内存马注入 列如 servlet  filter  listener Controller

**数据结构型**的特征主要体现在它们通过操作数据结构来实现其功能例如：

- PHP不死马中的**共享资源的访问条件竞争**
- C/C++内存马中的**恶意共享库的自定义加载机制**
- Python内存马中的**全局解释器锁（GIL）**和其他内存分配策略的操纵
- .NET内存马中的**持久连接**和**隐秘的数据交换**

哥斯拉：哥斯拉工具中有FilterShell和memoryShell两种内存马这些内存马在运行时会创建和操作复杂的数据结构，会在内存中创建数据结构来存储和管理恶意代码的状态，或者使用数据结构来组织和管理被感染的系统的信息

蚁剑：通过字节码直接注入恶意函数，然后通过方法名调用 涉及到了Java的类加载机制和方法调用机制，这些机制背后都有复杂的数据结构在支持例如，Java的类加载器会使用数据结构来存储和管理已加载的类，而方法调用则需要操作调用栈这种数据结构

| 平台          | 数据结构型内存马组件             |
| ------------- | -------------------------------- |
| Tomcat        | Listener, Filter, Servlet, Valve |
| Weblogic      | Listener, Servlet                |
| Spring Boot   | Controller, Interceptor          |
| JBoss/WildFly | 微内核组件，服务组件，部署器组件 |
| Docker        | 容器逃逸技术                     |



#### **API型内存马 **

主要通过hook或替换目标API的方式来实现持久化控制和隐藏，并不直接执行恶意代码，而是通过操纵正常API调用来达到目的

API接口型:通过挂钩或替换目标应用程序的API函数， 可以直接控制程序的执行流程，而且由于其是基于API的，所以更加稳定，不容易出错但是，API型内存马也有其缺点，那就是它需要知道目标应用程序的API函数地址，这就要求攻击者对目标系统的API有深入的了解此外，API型内存马也会影响到正常的API调用，从而导致程序出现异常，javaagent和javassist技术的内存马 API接口型

| 所使用的API技术                   | 恶意功能实现方法               | 防御措施                                                     |
| --------------------------------- | ------------------------------ | ------------------------------------------------------------ |
| JavaAgent                         | 修改Tomcat的类加载过程         | 使用安全的类加载机制，限制不受信任的代码执行；部署入侵检测系统，监测异常行为 |
| JavaAgent                         | 修改WebLogic的类加载过程       | 同上                                                         |
| JavaAgent                         | 修改Spring Boot的类加载过程    | 同上                                                         |
| JMX                               | 通过JMX API实现恶意功能        | 禁用不必要的JMX远程访问；使用安全的通信协议和认证机制；限制JMX访问的网络范围 |
| Docker API                        | 通过Docker API实现恶意功能     | 对Docker API访问进行身份验证和授权；限制网络访问，使用安全的通信协议；定期检查容器的安全配置 |
| JPA                               | 通过JPA API实现恶意功能        | 对数据库操作进行严格的权限控制；审计数据库活动，检测异常行为 |
| Kubernetes API                    | 通过Kubernetes API实现恶意功能 | 对Kubernetes API访问进行严格的权限控制；监控集群活动，检测异常行为；确保使用的Kubernetes版本没有已知的安全漏洞 |
| Javassist（字节码操作库 并非API） | 动态修改或生成恶意字节码       | 实现严格的代码签名和验证机制；使用沙箱环境限制代码执行；监控应用程序行为，检测异常 |



**API型**的特征主要体现在它们调用了特定的函数或方法来实现其功能例如：

1. **工作机制**：
   - 挂钩API：API型内存马通常会挂钩系统或应用程序的关键API函数，比如文件操作、网络通信或进程管理相关的函数当这些API被调用时，内存马可以先截获请求，执行额外的恶意操作，然后再将请求传递给原始的API函数
   - 替换API：在某些情况下，替换原有的API函数，用自己的版本来代替，API调用实际上都是在执行内存马中的代码
2. **特点**：
   - 隐蔽性：由于API型内存马是通过操纵正常的API，不直接执行恶意代码，因此它很难被AV/IPS发现
   - 灵活性：内存马可以根据需要挂钩或替换任意数量的API，这使得攻击者可以灵活地定制其行为
3. **检测和清除**：
   - 使用专门的API钩子检测工具：这类工具可以识别出哪些API被挂钩或替换，并帮助恢复原始的API函数
   - 分析系统日志和API调用记录：通过对比正常的API调用模式和当前的调用情况，可以发现潜在的异常行为
   - 使用内存取证技术：通过对内存转储进行分析，可以找出内存中的恶意代码片段



##### JavaAPI型内存马

​	**依赖Java版本，2004年后 Java5开始支持javaagent技术  兼容性高 各web容器可用  跨版本能力强**

1. **Javaagent技术**：
   - Javaagent技术允许开发者在Java应用程序启动时（通过premain方法）或者在运行时（通过agentmain方法）加载并执行代码这意味着内存马可以利用Javaagent技术，在应用程序启动时或者在运行时植入恶意代码，而不需要重新编译或部署整个应用程序
   - 内存马可以利用Javaagent技术提供的Instrumentation API来修改类的字节码，从而实现持久化驻留在内存中，而不留下任何文件级别的痕迹这使得内存马更难被检测和清除
2. **Javassist技术**：
   - 可以在运行时使用java编码动态修改和生成Java类的字节码，而无需了解底层的虚拟机指令内存马利用这个特性，在运行时动态地修改类定义，执行恶意操作，或者注入新的功能，由于Javassist提供的高级API使得操作字节码变得相对简单，内存马可以利用这一便利性，更容易地实现其恶意目的，同时也提高了自身的隐蔽性和生存能力

列子：

冰蝎4.0API内存马

​	冰蝎4.0API内存马在Java应用程序启动时或运行时加载恶意代码利用Java的Instrumentation API来修改类的字节码，从而实现持久化驻留在内存中，而不留下任何文件级别的痕迹冰蝎4.0API内存马还可以利用Javassist技术，在运行时动态地修改类定义，执行恶意操作，或者注入新的功能

1. **利用Instrumentation API**：Instrumentation API允许应用程序在运行时修改或动态地重新加载类攻击者可以通过这个API来注入恶意的类或代码

```java
import java.lang.instrument.Instrumentation;

public class MyAgent {
    public static void premain(String agentArgs, Instrumentation inst) {
        // 利用Instrumentation API来修改类
        Class<?> targetClass = inst.getClassDefinition("TargetClass");
        byte[] modifiedBytes = modifyClassBytes(targetClass);
        inst.redefineClasses(new ClassDefinition(targetClass, modifiedBytes));
    }

    private static byte[] modifyClassBytes(Class<?> targetClass) {
        // 这里应该包含修改字节码的逻辑
        // 例如，插入恶意的代码片段
        return new byte[] { /* ... modified bytecode ... */ };
    }
}
```

2. **利用Javassist技术**：Javassist是一个开源工具，它允许在Java运行时修改类文件

```java
import javassist.*;

public class MyJavassistAgent {
    public static void injectCode() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.get("TargetClass");
        
        // 插入恶意代码
        CtMethod method = ctClass.getDeclaredMethod("targetMethod");
        String injectCode = "System.out.println(\"Malicious operation executed.\");";
        method.insertBefore(injectCode);
        
        // 将修改后的类加载到JVM中
        Class<?> modifiedClass = ctClass.toClass();
    }
}
```

在上述示例中，`MyAgent`类展示了如何使用Instrumentation API来修改一个已加载的类`MyJavassistAgent`则展示了如何使用Javassist库来插入恶意代码，另外其他语言同样存在API调用 导致内存马利用

- PHP不死马中的**URL回连**，这是通过网络API实现的
- C/C++内存马中的**dlopen()**、**system()**、**popen()**、**fork()**、**malloc()**、**calloc()**和**realloc()**都是API调用
- Python内存马中的**importlib**、***\*import\****、**threading**和**multiprocessing**库的使用，以及通过HTTP请求反馈系统状态，
- .NET内存马中的**反射**、**程序集加载**、**代码混淆**和**事件绑定**，



**两者区别在于API是语言独有通常为java且依赖版本（服务架构设计原因），而数据结构型则是通用（计算机底层原理）依赖容器版本 种类繁多 ，不同容器和高低版本也会有差异 所以导致了不同种类的数据结构内存马**



#### 混合内存马

**基于不同目标产生不同编写手法会出现混合内存马 既调用数据结构也调用API，具体看侧重方向 **

1. **银行木马与系统进程**：

   **操纵数据结构**：银行木马操纵浏览器或支付平台的插件数据结构，插入一个恶意插件，用于窃取用户输入的敏感信息

   **挂钩API**：该木马挂钩网络通信API，如SSL/TLS库函数，来解密和篡改传输中的数据

   

2. **特种马**：

   操纵数据结构

   - **隐藏进程和驱动**：特种马会修改操作系统中关键的数据结构，例如系统进程表和驱动程序列表，以便隐藏自己的进程和驱动程序这样做的目的是使得恶意进程和驱动不易被发现，从而绕过安全软件的检测

   挂钩API

   - **拦截和修改系统调用**：特种马挂钩（hook）某些关键的系统调用API，例如`NtCreateFile`、`NtDeviceIoControlFile`等通过这种方式，特种马可以监控和修改这些系统调用的行为，进而控制文件访问、设备操作等系统级功能这也使得特种马能够拦截文件操作，进行数据窃取或者阻止安全软件的正常工作

   

3. **键盘记录器**：

   **操纵数据结构**：键盘记录器修改系统输入缓冲区的数据结构，以便捕获用户的按键事件

   **挂钩API**：同时，键盘记录器会挂钩键盘输入API，如`GetAsyncKeyState`，来实时监控用户的键盘操作

   

键盘记录器示例

   键盘记录器会尝试修改键盘缓冲区的结构来拦截按键事件

   ```python
import ctypes

# 定义Windows输入事件结构体
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
    ]

# 模拟按键事件的函数（伪代码）
def simulate_key_event(key_info):
    # 这里应该包含模拟按键事件的逻辑
    pass

# 记录按键的函数
def record_key_press(vk_code):
    # 这里应该包含记录按键的逻辑
    pass

# 主函数，用于记录键盘输入
def record_keyboard():
    while True:
        # 获取按键信息（伪代码）
        key_info = get_key_info()
        if key_info:
            record_key_press(key_info.wVk)
            # 模拟按键事件，以避免用户注意到输入延迟
            simulate_key_event(key_info)

# 启动键盘记录器
record_keyboard()
   ```

   **API挂钩示例**

   ```python
import ctypes

# 导入user32.dll中的原始GetAsyncKeyState函数
_original_get_async_key_state = ctypes.windll.user32.GetAsyncKeyState

# 自定义的GetAsyncKeyState函数，将拦截键盘输入
def get_async_key_state_hook(vk_code):
    # 在这里添加记录键盘输入的代码
    record_key_press(vk_code)
    
    # 调用原始的GetAsyncKeyState函数以获取真实的键盘状态
    return _original_get_async_key_state(vk_code)

# 安装API挂钩的函数（伪代码）
def install_hook(dll_name, func_name, hook_func):
    # 这里应该包含安装挂钩的逻辑
    pass

# 挂钩GetAsyncKeyState函数
install_hook("user32.dll", "GetAsyncKeyState", get_async_key_state_hook)

# 启动键盘输入挂钩
def hook_keyboard():
    # 这里应该包含启动挂钩的逻辑
    pass

# 开始挂钩
hook_keyboard()
   ```

   

#### 内核内存马

**系统内核马：直接作用于操作系统的内核层面，而不是普通的应用程序级别，根据不同的系统实现，Windows liunx MAC，利用对应的系统漏洞，内核模块和内核内存修改来进行注入系统内核马**

1. **Ebpf内核马**：这是一种新型的内核马，它通过eBPF（扩展Berkeley包装器）技术钩入内核的入口和出口流量，筛选出特定的恶意命令，并通过钩住execve等函数，将其他进程正常执行的命令替换为恶意命令，达到WebShell的效果这种内存马的特点是无进程、无端口、无文件（注入后文件可删除），执行命令不会新建shell进程，无法通过常规行为检测，且将WebShell注入内核，无法通过常规内存检测

   **在这个示例中，我们定义eBPF钩住`sys_execve`和`do_exit`函数当任何进程尝试执行一个新的程序时，都会调用`sys_execve`函数，eBPF程序将在每次调用`sys_execve`时运行，并从寄存器中获取要执行的命令如果命令是`/bin/bash`，我们将检查当前进程是否在`blocked_pids` map中如果在，我们将打印一条消息并阻止执行我们还钩住了`do_exit`函数，当进程退出时，将从`blocked_pids` map中删除对应的条目**

   ```c
   #include <linux/bpf.h>
   #include <linux/filter.h>
   #include <linux/kprobes.h>
   #include <linux/sched.h>
   #include <linux/bpf_perf_event.h>
   
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 1024);
       __type(key, pid_t);
       __type(value, int);
   } blocked_pids SEC(".maps");
   
   SEC("kprobe/sys_execve")
   int kprobe__sys_execve(struct pt_regs *ctx)
   {
       char *argv[64];
       int i;
       pid_t pid = bpf_get_current_pid_tgid();
   
       // 从寄存器中获取参数
       for (i = 0; i < 64; i++)
       {
           if (PT_REGS_PARM1(ctx) == 0)
               break;
           argv[i] = (char *)PT_REGS_PARM1(ctx);
           PT_REGS_PARM1(ctx) += sizeof(char *);
       }
   
       // 检查是否是要执行的命令是我们想要过滤的命令
       if (strcmp(argv[0], "/bin/bash") == 0)
       {
           // 检查当前进程是否在blocked_pids中
           if (bpf_map_lookup_elem(&blocked_pids, &pid))
           {
               printk(KERN_INFO "Attempted to execute /bin/bash by blocked pid %d\n", pid);
               return 1; // 阻止执行
           }
       }
   
       return 0;
   }
   
   SEC("kprobe/do_exit")
   int kprobe__do_exit(struct pt_regs *ctx)
   {
       pid_t pid = bpf_get_current_pid_tgid();
   
       // 当进程退出时，从blocked_pids中删除对应的条目
       bpf_map_delete_elem(&blocked_pids, &pid);
   
       return 0;
   }
   
   char _license[] SEC("license") = "GPL";
   ```

2. **内核级rootkits**：可以通过修改内核内存中的数据结构或系统调用来实现其恶意目的例如，它们会修改内核的进程表，使得恶意进程看起来像是合法的系统进程，从而避免被安全软件检测到或者，它们会修改系统调用表，使得某些系统调用被恶意代码接管，从而实现对系统的控制

   **示列：钩住了`schedule`和`kill`和`proc_file_operations`函数，隐藏特定的进程和文件**

   ```c
   #include <linux/module.h>
   #include <linux/kernel.h>
   #include <linux/sched.h>
   #include <linux/kallsyms.h>
   #include <linux/fs.h>
   
   static void (*old_schedule)(void) = NULL;
   static void (*old_kill)(pid_t pid, int sig) = NULL;
   static struct file_operations *(*old_proc_file_operations)(const char *name) = NULL;
   
   static void new_schedule(void)
   {
       printk(KERN_INFO "schedule function has been called\n");
       old_schedule();
   }
   
   static int new_kill(pid_t pid, int sig)
   {
       if (pid == 1234) // 假设我们要隐藏的进程的PID是1234
           return 0; // 忽略这个信号
       return old_kill(pid, sig);
   }
   
   static struct file_operations *new_proc_file_operations(const char *name)
   {
       if (strcmp(name, "cmdline") == 0) // 假设我们要隐藏的文件是/proc/cmdline
           return NULL; // 返回NULL表示这个文件不存在
       return old_proc_file_operations(name);
   }
   
   static int __init init_hook(void)
   {
       old_schedule = (void *)kallsyms_lookup_name("schedule");
       old_kill = (void *)kallsyms_lookup_name("kill");
       old_proc_file_operations = (void *)kallsyms_lookup_name("proc_file_operations");
   
       if (old_schedule && old_kill && old_proc_file_operations)
       {
           printk(KERN_INFO "Hooking schedule, kill and proc_file_operations functions\n");
           *(unsigned long *)old_schedule = (unsigned long)new_schedule;
           *(unsigned long *)old_kill = (unsigned long)new_kill;
           *(unsigned long *)old_proc_file_operations = (unsigned long)new_proc_file_operations;
       }
       return 0;
   }
   
   static void __exit cleanup_hook(void)
   {
       if (old_schedule && old_kill && old_proc_file_operations)
       {
           printk(KERN_INFO "Unhooking schedule, kill and proc_file_operations functions\n");
           *(unsigned long *)old_schedule = (unsigned long)old_schedule;
           *(unsigned long *)old_kill = (unsigned long)old_kill;
           *(unsigned long *)old_proc_file_operations = (unsigned long)old_proc_file_operations;
       }
   }
   
   module_init(init_hook);
   module_exit(cleanup_hook);
   
   MODULE_LICENSE("GPL");
   ```







### 内存马检测

#### **注入点的识别：**

1. Web应用漏洞：常见的注入点包括WebLogic、Tomcat、Jboss等Java容器，以及IIS.NET等Windows平台的应用服务器，这些环境下的反序列化漏洞是内存马常用的注入方式之一

2. 日志分析：检查web日志，寻找可疑的web访问日志，特别是大量URL请求路径，这可能是内存马活动的迹象

3. **异常流量分析**：通过分析网络流量，可以检测到异常的请求模式，这可能表明有内存马活动。例如，大量的短连接请求、重复的请求或来自同一IP地址的大量请求都可能是内存马活动的迹象。

   

   

#### *特征分析：*

​	1.字节码分析：利用sa-jdi.jar和tools.jar工具包获取JVM中的字节码，识别LAMBDA表达式和动态代理等隐蔽的内存马特征，这种方	法适用于Java环境下的内存马检测
​	

​	2.堆栈异常分析：对于非Java环境，可以通过排查线上程序出现的内存泄漏或溢出、死锁等问题，快速分析堆栈异常情况，找到问题	代码进行修复

​	3.行为分析**：内存马的行为模式可能与正常的应用程序行为有所不同。例如，内存马可能会尝试访问敏感数据、执行非法命令或	与外部服务器通信。通过对这些行为模式的监控和分析，可以发现潜在的内存马。**

​	4.内存快照分析**：通过定期捕获内存快照，可以比较不同时间点内存状态的差异。如果发现某些内存区域在多次快照中发生了不寻	常的变化，这可能表明有内存马在内存中执行



### 内存马防御

#### **1.Instrument的Agent检测**：

通过Java的Instrumentation API，动态地修改正在运行的JVM中的类定义。编写一个jar包Agent，在JVM启动时或者运行时attach到这个JVM上。这个Agent可以获取到所有已加载的类的信息，然后根据你定义的可疑特征进行检测

**优点是不会改变系统的运行状态，只是在检测过程中消耗资源**

**缺点是如果恶意代码不是直接写在某个类中，而是通过调用链调用的，那么检测难度会大大增加**

**步骤核心：将内存马变为webs hell对抗**

Attach检测

- 使用工具（如JVisualVM或JConsole）附加到正在运行的JVM进程上，以监控和分析该进程的内存使用、线程活动和类加载情况

获取已加载类列表

- 一旦附加到JVM，您可以获取当前进程中已经加载的类的完整列表。这将帮助您了解哪些类是活动的，并为进一步分析提供基础数据

可疑类反编译

- 从获取的已加载类列表中，挑选出可疑的类（基于先前的知识或某些异常指标）。然后，使用工具（如jd-gui或IntelliJ IDEA的反编译功能）将这些类文件反编译成Java源码

Webshell源码检测

- 对于反编译得到的Java源码，进行人工或自动化的代码审查，以识别任何不寻常的编程模式、可疑的网络通信、加密函数调用或其他恶意行为，从而确认是否为Webshell

文件中提到的“Attach检测”是一种针对Java应用程序的运行时分析方法，用于检测内存马等恶意行为。以下是该方法的详细步骤和示例：

**示例代码**

假设我们使用jd-gui工具对一个可疑的类进行反编译

```java
public class SuspiciousClass extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String secretCommand = request.getParameter("cmd");
        if (secretCommand != null && secretCommand.equals("secret")) {
            // 潜在的恶意行为：执行系统命令
            String[] command = {"/bin/bash", "-c", secretCommand};
            Runtime.getRuntime().exec(command);
        }
    }
}
```

在上述示例中，`SuspiciousClass`继承自`HttpServlet`，它在处理GET请求时，会检查请求参数`cmd`。如果参数存在并等于"secret"，它将执行一个名为`secretCommand`的系统命令。这可能表明该类被用来执行远程代码，这是一种典型的Webshell行为



#### 2.**中间件热部署特性**

将检测代码加载到服务的JVM中，用以检测Tomcat、JBoss、WebLogic等主流的具有热部署特性的Java Web中间件，比如著名的C0ny1大神开源的java-memshell-scanner工具，就是通过一个jsp脚本来扫描Java Web中间件中Filter，Servlet和Listener组件



#### 3.**RASP运行时防护**：

RASP（Runtime Application Self-Protection）是一种在应用程序运行时进行安全防护的技术。它可以感知到应用程序内部的各种行为，包括内存马在内存中的执行。例如，你可以在Filter类型的内存马创建的阶段进行hook，从而在早期就检测到风险，RASP通常与其他安全措施（如防火墙、入侵检测系统等）结合使用，以提供多层防御。

- **优点**：
  - 实时防护：能够立即检测和响应攻击。
  - 准确性强：通过在应用内部进行监控，可以更准确地识别恶意行为。
  - 误报率低：针对性的检测可以减少误判的可能性。

- **缺点**：
  - 侵入性强：需要修改应用程序代码或部署额外的组件。
  - 资源消耗：可能会增加应用程序的CPU和内存使用。

RASP运行时防护示例

假设我们有一个Web应用，我们想要保护这个应用不受恶意Filter的影响。我们可以创建一个自定义的Filter，这个Filter会在请求处理管道的早期阶段检查其他Filter和Servlet是否可疑

```java
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class SecurityFilter implements Filter {
    private static final Set<String> BLACKLISTED_CLASSES = new HashSet<>();

    static {
        // 黑名单中的类名，这些类可能是已知的恶意类
        BLACKLISTED_CLASSES.add("MaliciousFilter");
        BLACKLISTED_CLASSES.add("BackdoorServlet");
        // 可以添加更多的已知恶意类名
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Filter初始化时可以执行的操作
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();

        // 检查请求URI是否指向黑名单中的类
        if (BLACKLISTED_CLASSES.stream().anyMatch(className -> requestURI.contains(className))) {
            throw new ServletException("Detected attempt to access blacklisted class: " + requestURI);
        }

        // 如果检查通过，则继续过滤器链
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Filter销毁时可以执行的操作
    }
}
```

**在这个例子中，`SecurityFilter`会在请求处理管道中执行，检查每个请求的URI是否尝试访问已知的恶意类。如果检测到恶意行为，它将抛出一个`ServletException`来终止请求处理。**





#### 4**.内存保护和内存完整技术**：

基于内存保护技术和基于内存完整性的主动防御体系，该体系能够在程序执行期间阻止攻击能力，及时阻止内存滥用问题，并实现业务上下文关联分析，发现应用程序内部威胁，独立于操作系统的虚拟化管理层，并利用虚拟化监控技术和应用层Hook技术，能够综合检测识别内存马，内存安全产品采用硬件虚拟化技术架构，其中主要有两个环节：**防御与管理**

![](D:\OneDrive\图片\本机照片\脑图 (1).png)



#### **5.Linux下内存映射型内核级木马的隐藏和检测技术**

Rootkit技术是一种高级的隐藏技术，它通过修改内核结构来隐藏木马的存在。这种技术可能包括以下几个步骤：

1. 劫持系统调用：Rootkit会替换关键的系统调用，以便在系统层面隐藏自身或其创建的进程。
2. 内核模块注入：Rootkit可能会将自身注入到内核模块中，从而在内核级别运行代码并隐藏木马。
3. 环境伪装：Rootkit可能会修改系统环境，使木马进程看起来像正常的系统进程。

隐性存储技术

隐性存储技术通过将木马的数据存储在不易察觉的地方来提高隐蔽性，例如：

1. 文件系统伪装：将木马数据存储在看起来像是正常文件的伪装文件中。
2. 内存映射：将木马数据映射到操作系统使用的内存区域中，使其与系统数据混在一起。

检测技术

QEMU虚拟化技术

QEMU是一种开源的虚拟机软件，它可以用来模拟完整的计算机系统。利用QEMU进行检测的步骤可能包括：

1. 创建虚拟环境：在宿主机上创建一个虚拟机，并让可疑程序在虚拟机中运行。
2. 监控和分析：QEMU可以提供对虚拟机内存和系统调用的详细监控，从而帮助分析是否存在木马。

基于虚拟机架构的计数追踪检测原型

这种检测技术利用了虚拟机监视器的结构特性，通过追踪进程在执行过程中的系统调用计数来检测木马。步骤如下：

1. 安装监视器：在宿主机上安装能够监控系统调用计数的虚拟机监视器。

2. 追踪和分析：运行可疑程序，并通过监视器记录和分析系统调用的次数

   ### 安装QEMU（如果尚未安装）

   ```bash
   sudo apt-get update
   sudo apt-get install qemu qemu-system
   ```

   ### 创建一个虚拟机磁盘镜像

   ```bash
   qemu-img create my_vm_disk.qcow2 10G
   ```

   ### 下载并安装Linux操作系统

   1. 下载一个Linux发行版的ISO文件，例如Ubuntu Server。
   2. 使用QEMU将ISO写入到虚拟磁盘：

   ```bash
   qemu-system-x86_64 -hda my_vm_disk.qcow2 -cdrom /path/to/ubuntu-server.iso -boot d
   ```

   ### 安装Linux操作系统

   1. 启动后，根据QEMU的提示，通过虚拟机的图形界面完成操作系统的安装过程。
   2. 安装完成后，关闭虚拟机，并准备运行可疑程序。

   ### 运行可疑程序

   1. 将可疑程序上传到虚拟机中，或者通过某种方式在虚拟机内部生成该程序。
   2. 启动虚拟机并运行可疑程序：

   ```bash
   qemu-system-x86_64 -hda my_vm_disk.qcow2 -m 512 -boot c
   ```

   ### 使用QEMU监控工具进行分析

   QEMU提供了多种监控和分析工具，例如：

   - **GDB stub**：可以在QEMU运行时连接GDB调试器进行调试。
   - **KVM加速**：如果可用，可以使用KVM提高虚拟机的性能。
   - **系统调用跟踪**：可以使用strace等工具来跟踪程序的系统调用。

   #### 使用GDB进行调试

   1. 启动QEMU，使其监听用于GDB连接的端口：

   ```bash
   qemu-system-x86_64 -hda my_vm_disk.qcow2 -S -s
   ```

   2. 在另一个终端，使用GDB连接到QEMU：

   ```bash
   gdb
   (gdb) target remote localhost:1234
   ```

   #### 使用strace跟踪系统调用

   1. 进入虚拟机的命令行界面
   2. 使用strace跟踪可疑程序的系统调用：

   ```bash
   strace -f -o output.txt -p <PID_of_suspicious_program>
   ```

   ### 分析结果

   1. 收集所有监控工具的输出，包括GDB的日志、strace的输出文件等
   2. 使用文本编辑器或专用的分析工具来检查这些输出，寻找可疑的行为

   **通过上述步骤，可以使用QEMU对可疑的Linux程序进行全面的检测和分析，从而提高系统的安全性**

![](D:\OneDrive\图片\本机照片\image-20240423201545620.png)



#### 6.基于探索式分区和测试向量生成的硬件木马

硬件木马检测

基于探索式分区和测试向量生成的硬件木马检测方法则是一种新兴的技术，旨在提高集成电路中硬件木马检测的准确性和效率。这种方法结合了区域分割技术和优化的测试向量生成技术，以实现对硬件木马的有效检测。区域分割技术通过将电路设计为多个独立的区域，并为每个区域设计独立的供电网络和时钟控制，从而提高了侧信道数据在整体电路中的比重，使得含有硬件木马的电路与正常电路之间的差异更加明显。测试向量生成技术则是通过分析电路中惰性节点组合的分布规律，并利用人工蜂群算法等优化算法生成测试向量，可以有效提高测试向量的触发覆盖率，从而增强硬件木马的激活效果

该方法通过将电路分割成多个独立的区域，并针对每个区域设计独立的供电网络和时钟控制，提高了电路中不同部分之间的侧信道信息的差异，从而使含有硬件木马的部分更容易被识别出来。同时，通过使用优化算法生成高效的测试向量，可以更全面地覆盖电路的各个部分，提高检测的准确性和效率。

具体实现步骤包括：

1. 区域分割：根据电路的功能和结构将其划分为多个独立的子电路，每个子电路拥有独立的电源和时钟
2. 测试向量生成：利用优化算法（如人工蜂群算法）设计测试向量，以触发不同的电路状态，从而检测潜在的硬件木马

![](D:\OneDrive\图片\本机照片\01c033a7eb089396ef94a937e8b6854.png)

参考文献：

[内存马的攻防博弈之旅-腾讯云开发者社区-腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1955132)

[安芯网盾首发内存马攻击防护解决方案 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/360693550)

[饱受无文件攻击之苦？一文详解内存马攻击防范关键点 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/516783682)

[检索-中国知网 (cnki.net)](https://kns.cnki.net/kns8s/defaultresult/index?kw=硬件木马检测与防护)

[检索-中国知网 (cnki.net)](https://kns.cnki.net/kns8s/defaultresult/index?kw=主流木马技术分析及攻防研究)

